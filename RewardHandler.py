

import threading
import hashlib
import time


import Messages


lock = threading.Lock()


max_int32 = 0xFFFFFFFF


class RewardWaitHandler:

    def __init__(self, table):

        self.table = table

        self.reward_wait_list = dict()

    def wait_for_reward(self, dst_ip, mac):
        hash_str = hashlib.md5(dst_ip + mac).hexdigest()

        hash_value = int(hash_str, 16) & max_int32

        if hash_value not in self.reward_wait_list:
            reward_wait_thread = RewardWaitThread(
                dst_ip, mac, self.table, self.reward_wait_list)
            self.reward_wait_list.update({hash_value: reward_wait_thread})

            reward_wait_thread.start()

    def set_reward(self, reward_message):
        lock.acquire()
        try:
            self.reward_wait_list[reward_message.msg_hash].process_reward(
                reward_message.reward_value)

        except KeyError:
            pass

        finally:
            lock.release()


class RewardWaitThread(threading.Thread):

    def __init__(self, dst_ip, mac, table, reward_wait_list):
        super(RewardWaitThread, self).__init__()

        self.dst_ip = dst_ip

        self.mac = mac

        self.table = table

        self.reward_wait_list = reward_wait_list

        self.reward_is_received = False

        self.wait_timeout = 3

    def run(self):
        time.sleep(self.wait_timeout)

        if self.reward_is_received:
            pass

        else:
            self.table.update_entry(self.dst_ip, self.mac, 0)

        hash_str = hashlib.md5(self.dst_ip + self.mac).hexdigest()

        hash_value = int(hash_str, 16) & max_int32

        lock.acquire()
        try:
            del self.reward_wait_list[hash_value]

        except KeyError:
            pass

        finally:
            lock.release()

    def process_reward(self, reward_value):
        self.reward_is_received = True
        self.table.update_entry(self.dst_ip, self.mac, reward_value)


class RewardSendHandler:

    def __init__(self, table, raw_transport):

        self.table = table

        self.raw_transport = raw_transport

        self.node_mac = raw_transport.node_mac

        self.reward_send_list = dict()

        self.hold_on_timeout = 2

    def send_reward(self, dst_ip, mac):
        hash_str = hashlib.md5(dst_ip + mac).hexdigest()

        hash_value = int(hash_str, 16) & max_int32

        if hash_value not in self.reward_send_list:

            self.reward_send_list.update({hash_value: time.time()})
            self.send_back(dst_ip, mac)

        else:
            if (time.time() - self.reward_send_list[hash_value]) > self.hold_on_timeout:

                self.reward_send_list.update({hash_value: time.time()})
                self.send_back(dst_ip, mac)

    def send_back(self, dst_ip, mac):

        avg_value = self.table.get_avg_value(dst_ip)
        hash_str = hashlib.md5(dst_ip + self.node_mac).hexdigest()
        hash_value = int(hash_str, 16) & max_int32

        dsr_reward_message = Messages.RewardMessage(avg_value, hash_value)

        self.raw_transport.send_raw_frame(mac, dsr_reward_message, "")
