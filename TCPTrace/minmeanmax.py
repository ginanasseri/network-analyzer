class MinMeanMax:
    def __init__(self, data = [], data_min = None, data_mean = None, data_max = None):
        self.data = data
        self.data_min = data_min
        self.data_mean = data_mean
        self.data_max = data_max

    def get_mean(self):
        return sum(self.data) / len(self.data)

    def get_stats(self):
        self.data_min = round(min(self.data),6)
        self.data_mean = round(self.get_mean(),6)
        self.data_max = round(max(self.data),6)

    def stats_str(self, statement, unit):
        self.get_stats()
        print_str = f"Minimum {statement}: {self.data_min} {unit}\n"
        print_str += f"Mean {statement}: {self.data_mean} {unit}\n"
        print_str += f"Maximum {statement}: {self.data_max} {unit}\n"
        return print_str

class CompleteConnectionStats:
    def __init__(self, duration_data = [], RTT_data = [], packet_number_data = [], window_size_data = [], statement=None):
        self.duration_data = duration_data
        self.RTT_data = RTT_data
        self.packet_number_data = packet_number_data
        self.window_size_data = window_size_data

    def which_list(self, list_name):
        if list_name == "duration":
            return self.duration_data
        elif list_name == "RTT":
            return self.RTT_data
        elif list_name == "packet_number":
            return self.packet_number_data
        elif list_name == "window_size":
            return self.window_size_data
        else:
            raise ValueError(f"ConnectionStats: Invalid list name: {list_name}")

    def update_list(self, list_name, value):
        if list_name == "duration":
            self.duration_data.append(value)
        elif list_name == "RTT":
            self.RTT_data.append(value)
        elif list_name == "packet_number":
            self.packet_number_data.append(value)
        elif list_name == "window_size":
            self.window_size_data.append(value)
        else:
            raise ValueError(f"ConnectionStats: Invalid list name: {list_name}")

    def get_results(self):
        names = ["duration", "RTT", "packet_number", "window_size"]
        statements = ["time duration", "RTT value", "number of packets including both send/received", "window_size"]
        units = ["seconds", "", "", "bytes"]
        results_str = ""

        for name, statement, unit in zip(names, statements, units):
            curr_list = self.which_list(name)
            list_stats = MinMeanMax(curr_list)
            results = list_stats.stats_str(statement, unit)
#            results_str += results
            print(results)

#        return results 


