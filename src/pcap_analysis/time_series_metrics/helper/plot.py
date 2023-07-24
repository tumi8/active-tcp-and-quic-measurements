# Process Pcap file
#!/usr/bin/python

import os
import matplotlib.pyplot as plt
import matplotlib.dates as mdate

from time_series_metrics.helper.process_pcap import *
from time_series_metrics.helper.utils import *

# Function to plot all timeseries graph
def plot_all(config, flows):
    count = 0
    for flow in flows:
        count += 1
        flow_dir = get_output_dir_name(count)

        plot_timeseries(flow.tseries.rtt, "RTT", flow_dir)
        plot_timeseries(flow.tseries.outstanding_bytes, "Outstanding_Bytes", flow_dir)
        plot_timeseries(flow.tseries.sender_buffer, "Sender_Buffer", flow_dir)
        plot_timeseries(flow.tseries.retransmission, "Retransmission", flow_dir)
        plot_timeseries(flow.tseries.receiver_advertised_window, "Receiver_Advertised_Window", flow_dir)
        plot_timeseries(flow.tseries.throughput, "Throughput", flow_dir)
        plot_timeseries(flow.tseries.IAT_sender, "IAT_Sender", flow_dir)
        plot_timeseries(flow.tseries.IAT_receiver, "IAT_Receiver", flow_dir)
        plot_timeseries(flow.tseries.receive_buffer_utilisation, "Receive_Buffer_Utilisation", flow_dir)
        plot_timeseries(flow.tseries.receive_buffer_full, "Receive_Buffer_Full", flow_dir)

# Generic function to plot a timeseries
def plot_timeseries(data_list,name,flow_dir):
    # Return if list is empty
    if not data_list:
        return

    # Find initial time value to get relative time
    initial_time = data_list[0][0]

    # Construct graph name
    graph_name = str(name)+"_graph"

    # Get time series for x axis
    time_series = [item[0]-initial_time for item in data_list]
    # Get values for y axis
    values = [item[1] for item in data_list]

    # Draw a line graph
    fig, ax = plt.subplots()
    ax.plot(time_series, values)

    # Update graph attributes
    plt.title(graph_name)
    plt.xlabel('Time')
    plt.ylabel(name)

    # Save graph as image
    image_name = str(flow_dir)+"/"+str(name)+".png"
    plt.savefig(image_name)

    # Close plot
    plt.close()
