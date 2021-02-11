
import random
from math import e


class ValueEstimator:

    def __init__(self, est_method_id="avg"):

        self.actions = dict()

        if est_method_id == "avg":
            self.estimate_value = self.est_avg
        else:
            self.estimate_value = self.est_avg

    def estimate_value(self):
        pass

    def est_avg(self, action_id, reward):
        if action_id not in self.actions:

            self.actions.update({action_id: [0.0, 0]})

        estimated_value = (self.actions[action_id][0] * self.actions[action_id][1] + reward) \
            / (self.actions[action_id][1] + 1)

        estimated_value = round(estimated_value, 2)

        self.actions[action_id][0] = estimated_value

        self.actions[action_id][1] += 1

        return estimated_value

    def delete_action_id(self, action_id):
        if action_id in self.actions:
            del self.actions[action_id]


class act_select:

    def __init__(self, selection_method_id="greedy"):

        if selection_method_id == "greedy":
            self.select_action = self.select_action_greedy
            self.selection_method_id = "greedy"

        elif selection_method_id == "e-greedy":

            self.eps = 0.1
            self.select_action = self.select_action_e_greedy
            self.selection_method_id = "e-greedy"

        elif selection_method_id == "soft-max":
            self.select_action = self.select_action_softmax
            self.selection_method_id = "soft-max"

        else:
            self.select_action = self.select_action_greedy
            self.selection_method_id = "greedy"

    def select_action(self):
        pass

    def select_action_greedy(self, action_values):
        if len(action_values) == 0:
            return None

        return max(action_values, key=action_values.get)

    def select_action_e_greedy(self, action_values):
        if len(action_values) == 0:
            return None

        greedy_action_id = self.select_action_greedy(action_values)
        if random.random() > self.eps:
            return greedy_action_id
        else:

            chosen_action_id = random.choice(action_values.keys())

            while action_values[chosen_action_id] == greedy_action_id and len(action_values) != 1:
                chosen_action_id = random.choice(action_values.keys())
            return chosen_action_id

    def select_action_softmax(self, action_values):
        if len(action_values) == 0:
            return None

        tau = 1

        def calc_gibbs_boltzmann(values):
            probabilities = []

            denominator = 0.0
            for v in values:
                denominator += pow(e, (v / tau))

            for v in values:
                numerator = pow(e, (v / tau))
                probabilities.append(numerator / denominator)
            return probabilities

        def weighted_choice(items):
            weight_total = sum(items.values())

            def choice(uniform=random.uniform):
                n = uniform(0, weight_total)
                item = None
                for item in items:
                    if n < items[item]:
                        return item
                    n = n - items[item]
                return item
            return choice()

        action_weights = calc_gibbs_boltzmann(action_values.values())

        action = weighted_choice(
            dict(zip(action_values.keys(), action_weights)))
        return action
