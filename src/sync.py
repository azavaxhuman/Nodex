import json
import logging
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

class SyncManager:
    def __init__(self, api_manager, config_manager, traffic_state_manager):
        self.api_manager = api_manager
        self.config_manager = config_manager
        self.traffic_state_manager = traffic_state_manager

    @staticmethod
    def _to_int(val, default=0):
        try:
            if val is None:
                return default
            return int(val)
        except Exception:
            try:
                return int(str(val).strip())
            except Exception:
                return default

    @staticmethod
    def _now_ms():
        return int(time.time() * 1000)

    # --- Client identity helpers (protocol-aware) ---
    def _client_key(self, c, protocol: str):
        p = (protocol or "").lower()
        if not isinstance(c, dict):
            return None
        if p == "trojan":
            # Trojan: password is the unique identifier
            return c.get("password") or c.get("email") or c.get("id")
        elif p == "shadowsocks":
            # Shadowsocks: clientId is email
            return c.get("email")
        else:
            # vmess/vless: id or email
            return c.get("id") or c.get("email")

    def _client_id_for_api(self, c, protocol: str):
        p = (protocol or "").lower()
        if not isinstance(c, dict):
            return None
        if p == "trojan":
            return c.get("password")
        elif p == "shadowsocks":
            return c.get("email")
        else:
            return c.get("id")

    def _is_safu_fresh(self, c):
        """
        A fresh SAFU client is waiting for first use: startAfterFirstUse=True and expiryTime<=0
        """
        if not isinstance(c, dict):
            return False
        safu = bool(c.get('startAfterFirstUse'))
        exp = self._to_int(c.get('expiryTime'), 0)
        return safu and exp <= 0

    def _is_active_started(self, c, now_ms):
        """Client is active if expiryTime is in the future."""
        exp = self._to_int(c.get('expiryTime'), 0)
        return exp > now_ms

    def _is_ended(self, c, now_ms):
        """Client has ended if expiryTime is in the past or negative."""
        exp = self._to_int(c.get('expiryTime'), 0)
        return (exp > 0 and exp <= now_ms) or exp < 0

    # -------------------------------
    # Inbounds & Clients synchronization
    # -------------------------------
    def sync_inbounds_and_clients(self):
        central = self.config_manager.get_central_server()
        nodes = self.config_manager.get_nodes()

        try:
            central_session = self.api_manager.login(central)
            central_inbounds = self.api_manager.get_inbounds(central, central_session)
            if not central_inbounds:
                logging.error("No inbounds retrieved from central server, skipping sync")
                return
        except Exception as e:
            logging.error(f"Failed to connect to central server: {e}")
            return

        # Parse central inbounds and extract client lists
        parsed_central = []
        for ib in central_inbounds:
            settings = {}
            try:
                settings = json.loads(ib.get('settings') or '{}') or {}
            except Exception:
                pass
            parsed_central.append((ib, settings.get('clients', [])))

        for node in nodes:
            try:
                node_session = self.api_manager.login(node)
                node_inbounds = self.api_manager.get_inbounds(node, node_session)
                node_inbound_map = {inbound['id']: inbound for inbound in node_inbounds}

                # Synchronize inbounds (central -> node)
                for central_inbound, _ in parsed_central:
                    cid = central_inbound['id']
                    if cid not in node_inbound_map:
                        self.api_manager.add_inbound(node, node_session, central_inbound)
                    else:
                        # ==================== شروع جایگزینی از اینجا ====================
                        # یک کپی از اطلاعات اینباند مرکزی ایجاد می‌کنیم
                        data_for_node = central_inbound.copy()
                        
                        # اینباند فعلی را از روی نود پیدا می‌کنیم
                        current_node_inbound = node_inbound_map[cid]
                        
                        # --- ۱. نام (remark) را از نود می‌خوانیم و حفظ می‌کنیم ---
                        node_remark = current_node_inbound.get('remark', '')
                        data_for_node['remark'] = node_remark
                        
                        # --- ۲. پورت (port) را از نود می‌خوانیم و حفظ می‌کنیم ---
                        # اگر به هر دلیلی پورت وجود نداشت، 0 را به عنوان پیش‌فرض در نظر می‌گیریم
                        node_port = current_node_inbound.get('port', 0)
                        data_for_node['port'] = node_port
                        
                        # حالا بسته کامل شده را برای آپدیت ارسال می‌کنیم
                        self.api_manager.update_inbound(node, node_session, cid, data_for_node)
                        
                        node_inbound_map.pop(cid, None)
                        # ===================== پایان جایگزینی اینجا =====================

                # Remove inbounds that are not present on the central server
                for inbound_id in list(node_inbound_map.keys()):
                    self.api_manager.delete_inbound(node, node_session, inbound_id)

                # Synchronize clients with SAFU-aware policy
                now_ms = self._now_ms()

                for central_inbound, c_clients in parsed_central:
                    cid = central_inbound['id']

                    # Get clients from node
                    node_inbound = next((ni for ni in node_inbounds if ni['id'] == cid), None)
                    n_clients = []
                    if node_inbound:
                        try:
                            n_clients = (json.loads(node_inbound.get('settings') or '{}') or {}).get('clients', [])
                        except Exception:
                            n_clients = []

                    protocol = (central_inbound.get('protocol') or '').lower()

                    # Build protocol-aware client maps
                    n_client_map = { self._client_key(cl, protocol): cl for cl in n_clients if self._client_key(cl, protocol) }
                    c_client_map = { self._client_key(cl, protocol): cl for cl in c_clients if self._client_key(cl, protocol) }

                    # --- 1) If central has fresh SAFU clients: push them directly to node, skip merging
                    if any(self._is_safu_fresh(ccl) for ccl in c_clients):
                        for k, ccl in c_client_map.items():
                            if not self._is_safu_fresh(ccl):
                                continue  # Only process fresh SAFU clients
                            # Push to node (restore from Ended to SAFU)
                            if k in n_client_map:
                                nid = self._client_id_for_api(n_client_map[k], protocol)
                                # If exists on node, update
                                if nid is not None:
                                    try:
                                        self.api_manager.update_client(node, node_session, nid, cid, ccl)
                                    except Exception as _e:
                                        logging.error(f"Failed to push SAFU from central to node for client {k}: {_e}")
                            else:
                                # If not on node, add
                                try:
                                    self.api_manager.add_client(node, node_session, cid, ccl)
                                except Exception as _e:
                                    logging.error(f"Failed to add SAFU client {k} to node: {_e}")

                        # Continue to general PUSH phase (central -> node)
                        # (In this case, merging from node to central is intentionally skipped)

                    else:
                        # --- 2) If central does not have fresh SAFU: only promote active start time from node to central if needed
                        for k, ccl in c_client_map.items():
                            ncl = n_client_map.get(k)
                            if not ncl:
                                continue

                            central_exp = self._to_int(ccl.get('expiryTime'), 0)
                            node_exp    = self._to_int(ncl.get('expiryTime'), 0)

                            central_started_active = central_exp > now_ms
                            node_started_active    = node_exp > now_ms

                            should_promote = (not central_started_active) and node_started_active
                            if should_promote:
                                # Promote start time from node to central (minimum of positive values)
                                merged = node_exp if central_exp <= 0 else min(central_exp, node_exp)
                                if merged != central_exp and merged > now_ms:
                                    ccl['expiryTime'] = merged
                                    if 'startAfterFirstUse' in ccl and ccl.get('startAfterFirstUse') is True:
                                        ccl['startAfterFirstUse'] = False
                                    try:
                                        client_id = self._client_id_for_api(ccl, protocol) or self._client_id_for_api(ncl, protocol)
                                        if client_id is None:
                                            logging.warning(f"[SAFU-MERGE] Missing clientId for protocol={protocol} key={k} on inbound {cid}; central update skipped.")
                                        else:
                                            self.api_manager.update_client(central, central_session, client_id, cid, ccl)
                                            logging.info(f"[SAFU-MERGE] expiryTime merged to central for client {k} (inbound {cid}): {central_exp} -> {merged}")
                                    except Exception as _e:
                                        logging.error(f"Failed to update central client {k} after SAFU merge: {_e}")
                            # If node is Ended, do not promote to central

                    # --- 3) Final PUSH: central version (after above policy) to node
                    # Add or update clients
                    for ccl in c_clients:
                        k = self._client_key(ccl, protocol)
                        if k in n_client_map:
                            nid = self._client_id_for_api(n_client_map[k], protocol)
                            try:
                                self.api_manager.update_client(node, node_session, nid, cid, ccl)
                            except Exception as _e:
                                logging.error(f"Failed to update client {k} on node: {_e}")
                            # Remove from deletion candidates
                            n_client_map.pop(k, None)
                        else:
                            try:
                                self.api_manager.add_client(node, node_session, cid, ccl)
                            except Exception as _e:
                                logging.error(f"Failed to add client {k} on node: {_e}")

                    # Remove clients that are not present on central
                    for k, ncl in list(n_client_map.items()):
                        n_clid = self._client_id_for_api(ncl, protocol)
                        if n_clid is not None:
                            try:
                                self.api_manager.delete_client(node, node_session, cid, n_clid)
                            except Exception as _e:
                                logging.error(f"Failed to delete extra client {k} on node: {_e}")

            except Exception as e:
                logging.error(f"Error syncing with node {node['url']}: {e}")

    # -------------------------------
    # Traffic synchronization (V2)
    # -------------------------------
    def _fetch_node_traffic_parallel(self, nodes_by_url, node_sessions, email):
        """Parallelize traffic reads (I/O-bound only). Writes remain serial."""
        currents_by_server = {}
        futures = {}
        max_workers = min(len(node_sessions), self.config_manager.net().get('max_workers', 8))
        if max_workers <= 0:
            max_workers = 1

        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            for srv_url, sess in node_sessions.items():
                node = nodes_by_url.get(srv_url)
                if not node or not sess:
                    continue
                futures[ex.submit(self.api_manager.get_client_traffic, node, sess, email)] = srv_url

            for fut in as_completed(futures):
                srv_url = futures[fut]
                try:
                    n_up, n_down = fut.result()
                    currents_by_server[srv_url] = (n_up, n_down)
                except Exception as e:
                    logging.error(f"Traffic fetch failed for {email} on {srv_url}: {e}")
                    # مهم: روی خطا baseline لمس نشه → None برای skip در حلقه‌ی دلتا
                    currents_by_server[srv_url] = None

        return currents_by_server

    def sync_traffic(self):
        central = self.config_manager.get_central_server()
        nodes = self.config_manager.get_nodes()
        net_opts = self.config_manager.net()

        # دلخواه: سقف دلتا در هر اینتروال (بایت). اگر 0 یا منفی، غیرفعال.
        delta_cap = int(net_opts.get('delta_max_bytes_per_interval', 0) or 0)

        # Login to central server
        try:
            central_sess = self.api_manager.login(central)
        except Exception as e:
            logging.error(f"Failed to connect to central server: {e}")
            return

        # Get client list from central server
        try:
            central_inbounds = self.api_manager.get_inbounds(central, central_sess)
            if not central_inbounds:
                logging.error("No inbounds retrieved from central server, skipping traffic sync")
                return
        except Exception as e:
            logging.error(f"Failed to get inbounds from central server: {e}")
            return

        # Collect client emails from central server (including settings)
        client_emails = set()
        for inbound in central_inbounds:
            for client in inbound.get('clientStats') or []:
                if client and 'email' in client:
                    client_emails.add(client['email'])
            try:
                s = json.loads(inbound.get('settings') or '{}') or {}
                for c in s.get('clients', []):
                    e = c.get('email')
                    if e:
                        client_emails.add(e)
            except Exception:
                pass

        # Login to nodes (optional)
        node_sessions = {}
        for node in nodes:
            try:
                node_sessions[node['url']] = self.api_manager.login(node)
            except Exception as e:
                logging.error(f"Failed to login node {node['url']}: {e}")

        nodes_by_url = {node['url']: node for node in nodes}
        parallel_reads = net_opts.get('parallel_node_calls', True)

        for email in client_emails:
            try:
                # 1) Read current traffic from all servers
                currents_by_server = {}
                c_up, c_down = self.api_manager.get_client_traffic(central, central_sess, email)
                currents_by_server[central['url']] = (c_up, c_down)

                if parallel_reads and node_sessions:
                    currents_by_server.update(
                        self._fetch_node_traffic_parallel(nodes_by_url, node_sessions, email)
                    )
                else:
                    for srv_url, sess in node_sessions.items():
                        node = nodes_by_url.get(srv_url)
                        if not node or not sess:
                            continue
                        try:
                            n_up, n_down = self.api_manager.get_client_traffic(node, sess, email)
                            currents_by_server[srv_url] = (n_up, n_down)
                        except Exception as e:
                            logging.error(f"Traffic fetch failed for {email} on {srv_url}: {e}")
                            # مهم: روی خطا baseline لمس نشه → None برای skip در حلقه‌ی دلتا
                            currents_by_server[srv_url] = None

                # 2) Detect first time or central reset
                last_central = self.traffic_state_manager.get_last_counter(email, central['url'])
                if last_central is None:
                    # First observation of this user -> start cycle at central snapshot
                    self.traffic_state_manager.reset_cycle(email, currents_by_server, central['url'])
                    total_up, total_down = currents_by_server[central['url']]

                    # Write total to central + nodes; سپس baseline هر سرور = total (اگر write موفق بود)
                    try:
                        self.api_manager.update_client_traffic(central, central_sess, email, total_up, total_down)
                        self.traffic_state_manager.set_last_counter(email, central['url'], total_up, total_down)
                    except Exception as e:
                        logging.error(f"[INIT] Failed to write total to central for {email}: {e}")

                    for srv_url, sess in node_sessions.items():
                        node = nodes_by_url.get(srv_url)
                        if node and sess:
                            try:
                                self.api_manager.update_client_traffic(node, sess, email, total_up, total_down)
                                self.traffic_state_manager.set_last_counter(email, srv_url, total_up, total_down)
                            except Exception as e:
                                logging.error(f"[INIT] Failed to write total to node {srv_url} for {email}: {e}")

                    # total را در state هم بنویسیم تا پایدار باشد
                    self.traffic_state_manager.set_total(email, total_up, total_down)

                    logging.info(f"[INIT] {email}: total set to central current ({total_up},{total_down}); baselines initialized & aligned to total; node_totals cleared.")
                    continue

                last_cu, last_cd = last_central
                # IMPORTANT: consider central reset only if BOTH counters dropped (real reset)
                central_reset = (c_up < last_cu) and (c_down < last_cd)
                if central_reset:
                    # Start a new cycle (central reset) using current observations as baselines
                    self.traffic_state_manager.reset_cycle(email, currents_by_server, central['url'])
                    total_up, total_down = currents_by_server[central['url']]

                    # Write total to central + nodes; سپس baseline هر سرور = total (اگر write موفق بود)
                    try:
                        self.api_manager.update_client_traffic(central, central_sess, email, total_up, total_down)
                        self.traffic_state_manager.set_last_counter(email, central['url'], total_up, total_down)
                    except Exception as e:
                        logging.error(f"[CENTRAL RESET] Failed to write total to central for {email}: {e}")

                    for srv_url, sess in node_sessions.items():
                        node = nodes_by_url.get(srv_url)
                        if node and sess:
                            try:
                                self.api_manager.update_client_traffic(node, sess, email, total_up, total_down)
                                self.traffic_state_manager.set_last_counter(email, srv_url, total_up, total_down)
                            except Exception as e:
                                logging.error(f"[CENTRAL RESET] Failed to write total to node {srv_url} for {email}: {e}")

                    # total را هم ذخیره می‌کنیم
                    self.traffic_state_manager.set_total(email, total_up, total_down)

                    logging.warning(
                        f"[CENTRAL RESET] {email}: total reset to central current ({total_up},{total_down}); baselines reinitialized & aligned; node_totals cleared."
                    )
                    continue

                # 3) If no central reset: calculate per-server deltas (Scenario 1..3)
                total_up, total_down = self.traffic_state_manager.get_total(email)
                added_up, added_down = 0, 0

                for srv_url, cur_pair in currents_by_server.items():
                    # اگر خواندن نود fail بوده، این چرخه برای آن نود را نادیده بگیر و baseline را لمس نکن
                    if cur_pair is None:
                        logging.warning(f"[SKIP NODE] {email} @ {srv_url}: traffic read failed; keeping previous baseline.")
                        continue

                    cur_up, cur_down = cur_pair
                    last = self.traffic_state_manager.get_last_counter(email, srv_url)
                    if last is None:
                        # First observation from this server: baseline = current (delta 0)
                        self.traffic_state_manager.set_last_counter(email, srv_url, cur_up, cur_down)
                        continue

                    last_up, last_down = last

                    # Real reset on this node: BOTH directions dropped -> delta=0
                    if (cur_up < last_up) and (cur_down < last_down):
                        du = 0
                        dd = 0
                        logging.warning(
                            f"[NODE COUNTER DROP] {email} @ {srv_url}: "
                            f"last=({last_up},{last_down}) -> cur=({cur_up},{cur_down}); treat as reset (delta=0)."
                        )
                    else:
                        # Safe component-wise delta (no negatives)
                        du = max(0, cur_up - last_up)
                        dd = max(0, cur_down - last_down)

                    # دلتا غیرعادی را محدود کنیم (اختیاری)
                    if delta_cap > 0:
                        if (du + dd) > delta_cap:
                            logging.warning(f"[DELTA CLAMP] {email} @ {srv_url}: (du+dd)={(du+dd)} > cap={delta_cap}; clamped to 0 for this interval.")
                            du = 0
                            dd = 0

                    # Always update per-node baseline to the current observation
                    self.traffic_state_manager.set_last_counter(email, srv_url, cur_up, cur_down)

                    # Accumulate only positive deltas
                    if du > 0 or dd > 0:
                        added_up += du
                        added_down += dd
                        self.traffic_state_manager.add_node_delta(email, srv_url, du, dd)

                # 4) Add deltas and save new total (only if changed)
                changed = False
                if added_up != 0 or added_down != 0:
                    total_up += added_up
                    total_down += added_down
                    changed = self.traffic_state_manager.set_total(email, total_up, total_down)

                # 5) Write total to central and nodes; سپس baseline سرورِ موفق = total
                if changed:
                    # Central first
                    central_written = False
                    try:
                        self.api_manager.update_client_traffic(central, central_sess, email, total_up, total_down)
                        self.traffic_state_manager.set_last_counter(email, central['url'], total_up, total_down)
                        central_written = True
                    except Exception as e:
                        logging.error(f"[WRITE] Failed to write total to central for {email}: {e}")

                    # Nodes
                    for srv_url, sess in node_sessions.items():
                        node = nodes_by_url.get(srv_url)
                        if not node or not sess:
                            continue
                        try:
                            self.api_manager.update_client_traffic(node, sess, email, total_up, total_down)
                            # فقط اگر write موفق بود baseline را هم‌راستا کنیم
                            self.traffic_state_manager.set_last_counter(email, srv_url, total_up, total_down)
                        except Exception as e:
                            logging.error(f"[WRITE] Failed to write total to node {srv_url} for {email}: {e}")

                    logging.debug(f"[DELTA ADD] {email}: +({added_up},{added_down}) -> total=({total_up},{total_down})")

            except Exception as e:
                logging.error(f"Error syncing traffic for {email}: {e}")
