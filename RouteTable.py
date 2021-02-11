

import copy


import rl_logic
import routing_logging


PATH_TO_LOGS = routing_logging.PATH_TO_LOGS


TABLE_LOG = routing_logging.create_routing_log(
    "routing.route_table.log", "route_table")


class Entry(dict):

    def __init__(self, dst_ip, neighbors_list):
        super(Entry, self).__init__()

        self.dst_ip = dst_ip

        self.local_neighbor_list = copy.deepcopy(neighbors_list)

        self.init_values()

        self.value_estimator = rl_logic.ValueEstimator()

    def init_values(self):
        for mac in self.local_neighbor_list:
            if mac not in self:

                self.update({mac: 0.0})

    def update_neighbors(self, neighbors_list):
        if self.local_neighbor_list == neighbors_list:
            pass
        else:

            self.local_neighbor_list.update(neighbors_list)

            keys_to_delete = set(self.local_neighbor_list) - \
                set(neighbors_list)
            for key in keys_to_delete:

                del self.local_neighbor_list[key]

                self.value_estimator.delete_action_id(key)

            self.init_values()

    def update_value(self, mac, reward):

        self[mac] = self.value_estimator.estimate_value(mac, reward)

    def calc_avg_value(self):
        return sum(self.values()) / len(self)


class Table:

    def __init__(self, node_mac):

        self.table_filename = "table.txt"

        self.node_mac = node_mac

        self.neighbors_list = dict()

        self.entries_list = dict()

        self.current_node_ips = list()

        self.action_selector = rl_logic.act_select("soft-max")
        TABLE_LOG.info("Chosen selection method: %s",
                       self.action_selector.selection_method_id)

    def get_next_hop_mac(self, dst_ip):
        if dst_ip in self.entries_list:

            self.entries_list[dst_ip].update_neighbors(self.neighbors_list)

            next_hop_mac = self.action_selector.select_action(
                self.entries_list[dst_ip])
            TABLE_LOG.debug("Selected next_hop: %s, from available entries: %s",
                            next_hop_mac, self.entries_list[dst_ip])
            return next_hop_mac

        else:
            return None

    def update_entry(self, dst_ip, mac, reward):
        if dst_ip in self.entries_list:
            self.entries_list[dst_ip].update_value(mac, reward)
        else:
            TABLE_LOG.info("No such Entry to update. Creating and updating a new entry for dst_ip and mac: %s - %s",
                           dst_ip, mac)

            self.entries_list.update(
                {dst_ip: Entry(dst_ip, self.neighbors_list)})
            self.entries_list[dst_ip].update_value(mac, reward)

    def get_avg_value(self, dst_ip):
        if dst_ip in self.entries_list:
            avg_value = self.entries_list[dst_ip].calc_avg_value()
            TABLE_LOG.debug(
                "Calculated average value towards dst_ip %s : %s", dst_ip, avg_value)
            return avg_value

        else:
            TABLE_LOG.warning(
                "CANNOT GET AVERAGE VALUE! NO SUCH ENTRY!!! Returning 0")
            return 0.0

    def get_neighbors(self):
        neighbors_list = list(set(self.neighbors_list))
        TABLE_LOG.debug("Current list of neighbors: %s", neighbors_list)
        return neighbors_list

    def get_entry(self, dst_ip):
        if dst_ip in self.entries_list:
            return self.entries_list[dst_ip]
        else:
            return None

    def get_list_of_entries(self):
        current_keys = self.entries_list.keys()
        current_values = self.entries_list.values()

        while len(current_keys) != len(current_values):
            current_keys = self.entries_list.keys()
            current_values = self.entries_list.values()

        current_values = map(dict, current_values)

        return dict(zip(current_keys, current_values))

    def get_neighbors_l3_addresses(self):

        keys = self.neighbors_list.keys()
        values = self.neighbors_list.values()

        while len(keys) != len(values):
            keys = self.neighbors_list.keys()
            values = self.neighbors_list.values()

        neighbors_list = dict(zip(keys, values))

        addresses_list = []
        for mac in neighbors_list:
            addresses_list.append([])
            for addr in neighbors_list[mac].l3_addresses:
                if addr:
                    addresses_list[-1].append(addr)

        return addresses_list

    def print_table(self):
        current_entries_list = self.get_list_of_entries()

        f = open(PATH_TO_LOGS + self.table_filename, "w")
        f.write("-" * 90 + "\n")

        for dst_ip in current_entries_list:
            f.write("Towards destination IP: %s \n" % dst_ip)
            f.write("<Next_hop_MAC> \t\t <Value>\n")
            for mac in current_entries_list[dst_ip]:
                string = "%s \t %s \n"
                values = (mac, current_entries_list[dst_ip][mac])
                f.write(string % values)
            f.write("\n")
        f.write("-" * 90 + "\n")
        f.close()
