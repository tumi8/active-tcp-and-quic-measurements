# modified PPrate for optimal capacity estimation
import struct
import dpkt
import numpy as np

LINE_DIVISOR = '----------------------------------------------------'
DEFAULT_ETHERNET_MSS = 1460


def find_mss(raw_data):
    """Find and return the Maximum Segment Size of a flow."""
    # Iterate through segments in flow
    for segment in raw_data:
        # Inspect if SYN flag is set
        if segment.flags & dpkt.tcp.TH_SYN:
            # Search for MSS option
            options = dpkt.tcp.parse_opts(segment.opts)
            for option in options:
                # Return MSS value
                if option[0] == 2:
                    return struct.unpack(">H", option[1])[0]
    # Otherwise return default Ethernet value
    return DEFAULT_ETHERNET_MSS


def estimate_capacity(pcap: list) -> float:
    """
    Capacity in MBit/s

    Args:
        pcap: opened pcap file via dpkt

    Returns:
        estimated capacity
    """
    flow = parse_pcap(pcap)
    iats = get_iats(flow)
    ip_pdu_sizes = get_sizes(flow)
    return get_estimate_receiver(ip_pdu_sizes, iats) / 10 ** 6


def get_estimate_sender(time_stamps: list, raw_data: list):
    """
    Computes capacity based on ACK inter-arrival times.
    """

    # Sender side algorithm: count differences between ACK segments
    ip_data = list(map(lambda b: dpkt.ethernet.Ethernet(b).data, raw_data))
    acks = list(map(lambda b: b.data, ip_data))
    mss = find_mss(acks)

    # Get ACK segments without data
    acks = [f for f in acks if (f.data == b'' and (f.flags & dpkt.tcp.TH_ACK))]

    ret = []
    for i, x in enumerate(acks):
        if i == 0:
            pass
        else:
            ack = acks[i].ack - acks[i - 1].ack
            if ack % (mss - 12) == 0 and ack != 0:
                cnt = ack / (mss - 12)
                dif = float(time_stamps[i] - time_stamps[i - 1])
                ret.append(dif / cnt)
                continue

        # Scale results to seconds
    iats = np.array(ret, dtype=float)
    return find_capacity(mss, iats)


def get_estimate_receiver(mss: list, iats) -> float:
    length = len(iats)

    if length == 0:
        print('No data to process was found. IAT = 0')
        return -1

    print(length)
    if length < 250:
        # Replicate data if less than 250 samples
        print('Not enough data for estimation! Trying to replicate data, result may be overestimated...')
        iats, mss = replicate_data(iats, mss)
    return find_capacity(mss, iats)

def get_sizes(flow: list):
    # instead of mss take ip pdu size (alternative: take whole packet size)
    return [f[2] for f in flow if f[1].data != b''][1:]


def get_iats(flow: list):
    """
    Derive and return list of packet inter-arrival times of a single flow.
    NOTE: receiver side only
    """
    # Receiver side algorithm: count time difference between data segments
    # Get all data segments
    data = [f[0] for f in flow if f[1].data != b'']

    # inter-arrival times of data packets in seconds
    ret = list(map(lambda t: t[1] - t[0], zip(data, data[1:])))
    return np.array(ret, dtype=float)


# ############################################### LIBRARY FUNCTIONS ###################################################


def parse_pcap(pcap: list) -> list:
    """
    NOTE: assumption is, that only one flow is present in the pcap list (which has been filtered by tcpdump).
    Extract and manage single flow from the input packet capture file.

    Args:
        pcap: dpkt read pcap list

    Returns: single flow as packet list
    """
    flow = []

    # Collect packets and their corresponding timestamps
    for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)

        if eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.type != dpkt.ethernet.ETH_TYPE_IP6:
            # Skip non-IP packets
            continue

        ip = eth.data

        if ip.p == dpkt.ip.IP_PROTO_TCP or ip.p == dpkt.ip.IP_PROTO_ICMP:
            data = ip.data
            # Pack each packet from single flow as timestamp, tcp/icmp data, total IP PDU size
            # NOTE: instead of MSS size IP PDU size is taken to correct underestimation
            flow.append((ts, data, ip.len))

    return flow


def convert_si(value):
    if value >= 10**9:
        return '{} Gbps'.format(value / 10.0 ** 9)
    if value >= 10**6:
        return '{} Mbps'.format(value / 10.0 ** 6)
    if value >= 10**3:
        return '{} kbps'.format(value / 10.0 ** 3)
    return '{} bps'.format(value)


def slice_iats(list, pos, n):
    """Return n elements of list starting at pos"""
    return list[pos:pos + n]


def replicate_data(iats, sizes):
    """Extrapolate a too short data set by using the doubling approach"""
    ret_iats = iats
    ret_sizes = sizes
    while len(ret_iats) < 250:
        ret_iats = np.append(ret_iats, iats)
        ret_sizes.extend(ret_sizes)
    return ret_iats, ret_sizes


def interquartile_range(data):
    q3, q1 = np.percentile(data, [75, 25])
    return q3 - q1


def noise_cleaning(c):
    # Noise cleaning
    vhi = np.percentile(c, 75, interpolation='midpoint') + 1 * interquartile_range(c)
    vlo = np.percentile(c, 25, interpolation='midpoint') - 1 * interquartile_range(c)
    c = remove_zeroes([i for i in c if i <= vhi])
    c = remove_zeroes([i for i in c if i >= vlo])
    return c


def find_capacity(sizes, iats, verbose=False):
    """Find an capacity estimate by analyzing inter-arrival times and segment sizes using the PPrate approach."""

    # Exclude null values from input list
    iats = remove_zeroes(iats)

    # Calculate capacities using our formula
    if type(sizes) is int:
        refined_algo = False
        c = (sizes * 8) / iats
    elif type(sizes) is list:
        refined_algo = True
        c = get_distribution(iats, sizes)

    c = noise_cleaning(c)

    # Determine bin width and resolution
    res = int(np.floor(interquartile_range(np.array(c)) * 0.05))
    if res != 0:
        # Suppress division through 0
        nbin = int(np.ceil(max(c) / res))
    else:
        nbin = 1000
        res = max(c) / nbin

    if nbin > 1000:
        nbin = 1000
        res = max(c) / nbin

    if verbose:
        if res > 10 ** 6:
            flag = 2
            print('Capacity resolution: ' + str(res / 10 ** 6) + ' Mbps')
        elif res > 10 ** 3:
            flag = 1
            print('Capacity resolution: ' + str(res / 10 ** 3) + ' Kbps')
        else:
            flag = 0
            print('Capacity resolution: ' + str(res) + ' bps')

        print('Phase 1: Mode estimation using packet pairs...')

    modes = np.array([])

    try:
        modes = local_modes(c, nbin, res)
    except ValueError:
        if verbose:
            print('Could not detect modes! Please try again with a different flow capture.')
        return -1

    # Get amount of modes
    r = modes.shape[0]
    if r == 1:
        if verbose:
            print('Weak noise')
        capacity = float(modes[0, 1] * res - res / 2)
    else:
        if verbose:
            print('Phase 2: Estimating ADR...')

        step = 3
        cond = 1

        if refined_algo:
            # Use default Ethernet MSS as approximation for trains
            mss = 1460
        else:
            # Use MSS from parameter
            mss = sizes

        while r > 1 and step < 40 and cond:
            len = int(np.floor(iats.size / step))
            x = np.reshape(iats[0:(len * step)], (step, len), order='F')
            x = x[0: step - 1, :]
            x = np.sum(x, axis=0)
            b = ((step - 1) * mss * 8) / x
            modes_2 = local_modes(b, nbin, res)
            if (type(modes_2) == int) and (modes_2 == -1):
                return -1
            if modes_2.shape[0] == 1:
                max_mod = np.max(modes_2)
            else:
                max_mod = np.max(modes_2[:, 0])
            if max_mod < 15:
                cond = 0
            r = modes_2.shape[0]
            step += 1

        if r > 1:
            if verbose:
                print('Phase 2 did not lead to an unimodal distribution!')
                print('The capacity may be a bad estimate, please try again later.')
            ind = np.argmax(modes[:, 0])
            capacity = float(modes[ind, 1] * res - res / 2)
        else:
            adr = modes_2[0, 1] * res

            if verbose:
                if flag == 2:
                    print('ADR estimate: ' + str(adr / 10 ** 6) + ' Mbps')
                elif flag == 1:
                    print('ADR estimate: ' + str(adr / 10 ** 3) + ' kbps')
                else:
                    print('ADR estimate: ' + str(adr / 10) + ' bps')

            j = (modes[1:, 1] >= modes_2[0, 3]).nonzero()[0]
            j += 1
            # modes[1:,1]
            if np.size(j, 0) == 0:
                j = (modes[:, 1] <= modes_2[0, 3]).nonzero()[0]
                capacity = float(modes[j[-1], 1] * res - res / 2)
            else:
                ij = np.argmax(modes[j, 0])
                capacity = float(modes[j[ij], 1] * res - res / 2)

    # Return final estimate value
    return capacity


def local_modes(x, nbin, w):
    bell = []

    for i in range(1, nbin + 1):
        bell.append(len([j for j in x if j < i * w]))

    bell = np.append([0, 0], bell)
    bell = np.diff(bell)

    A = np.diff(bell)
    # Prepend and append -1
    A = np.insert(A, 0, -1, 0)
    A = np.insert(A, A.size, -1, axis=0)

    # Replace negative and 0 values with -1, positive with 1
    for i in range(0, A.size):
        if A[i] <= 0:
            A[i] = -1
        else:
            A[i] = 1

    # Add positive values to peak list if next element is negative
    peaks = np.array([]).astype(int)
    for i in (A == 1).nonzero()[0]:
        if A[i + 1] == -1:
            peaks = np.append(peaks, i + 1)

    if peaks.size == 0:
        # Raise exception in case no modes were detected
        return -1

    modes = np.zeros((peaks.size, 3))
    modes[:, 0] = peaks.conj().transpose()

    for i, y in enumerate(peaks):
        index = y
        while A[index - 2] == 1:
            index -= 1
        modes[i, 1] = index

        index = y
        while (index + 1 <= A.size) and (A[index] == -1):
            index += 1
        modes[i, 2] = index

    modes = clean_modes(bell, modes)
    peaks = intersection(peaks, modes[:, 0]).astype(int)
    modes = np.concatenate((np.array([bell[peaks - 1]]).T, modes), axis=1)
    return modes


def clean_modes(bell, modes):
    bell = bell.astype(int)
    modes = modes.astype(int)
    thres1 = 0.2
    thres2 = 0.15

    m, id = np.max(bell[modes[:, 0] - 1]), np.argmax(bell[modes[:, 0] - 1])

    peaks = bell[modes[:, 0] - 1]
    alpha = m * thres2
    li = (peaks < alpha).nonzero()[0]

    for i in range(0, li.size):
        modes = clean_matrix(li[i], modes)
        li = li - 1

    r = np.size(modes, 0)
    m, id = np.max(bell[modes[:, 0] - 1]), np.argmax(bell[modes[:, 0] - 1])

    for i in range(id, r - 1):
        a = np.abs(bell[modes[i + 1, 0] - 1] - bell[modes[i, 2] - 1])
        b = a
        if (i + 2) < r:
            b = np.abs(bell[modes[i + 1, 0] - 1] - bell[modes[i + 1, 2] - 1])
        min_ab = min(a, b)
        if min_ab <= bell[modes[i + 1, 0] - 1] * thres1:
            modes[i + 1, 0] = 0
            sub = modes[id:i + 1, 0].ravel().nonzero()[0]
            indx = sub[-1] + id
            modes[indx, 2] = modes[i + 1, 2]

    modes = clean(modes)

    m, id = np.max(bell[modes[:, 0] - 1]), np.argmax(bell[modes[:, 0] - 1])
    for i in range(id, 0, -1):
        a = np.abs(bell[modes[i - 1, 0] - 1] - bell[modes[i, 1] - 1])
        if i - 1 > 0:
            b = np.abs(bell[modes[i - 1, 0] - 1] - bell[modes[i - 2, 2] - 1])
        elif bell[modes[i - 1, 0] - 1] != bell[modes[i - 1, 1] - 1]:
            b = np.abs(bell[modes[i - 1, 0] - 1] - bell[modes[i - 1, 1] - 1])
        else:
            b = bell[modes[i - 1, 1] - 1]

        min_ab = min(a, b)
        if min_ab <= bell[modes[i - 1, 0] - 1] * thres2:
            modes[i - 1, 0] = 0
            sub = modes[(i - 1):id + 1, 0].ravel().nonzero()[0]
            indx = sub[0] + i - 1
            modes[indx, 1] = modes[i - 1, 1]

    modes = clean(modes)

    r = np.size(modes, 0)
    if r == 1:
        l_bell = np.size(bell, 0)
        if modes[0, 2] > l_bell:
            modes[0, 2] = l_bell

        c = float(bell[modes[0, 2] - 1]) / float(bell[modes[0, 0] - 1])

        if c > 0.01:
            while (c > 0.01) & (modes[0, 2] < l_bell):
                modes[0, 2] = modes[0, 2] + 1
                c = float(bell[modes[0, 2] - 1]) / float(bell[modes[0, 0] - 1])
        else:
            while c < 0.01:
                modes[0, 2] = modes[0, 2] - 1
                c = float(bell[modes[0, 2] - 1]) / float(bell[modes[0, 0] - 1])

    return modes


def intersection(i1, i2):
    l1 = np.size(i1, 0)
    i = []

    for x in range(0, l1):
        if np.size((i2 == i1[x]).nonzero()[0], 0) == 0:
            pass
        else:
            i = np.append(i, i1[x])
    return i


def clean_matrix(i, matrix):
    """Delete row i from matrix"""
    return np.delete(matrix, i, axis=0)


def remove_zeroes(list):
    """Remove zeroes from array"""
    return np.array([i for i in list if i != 0])


def clean(mode):
    """Remove leading zero rows from mode matrix"""
    i = (mode[:, 0] == 0).nonzero()[0]
    while np.size(i, 0) != 0:
        mode = clean_matrix(i[0], mode)
        i = (mode[:, 0] == 0).nonzero()[0]
    return mode


def get_distribution(iats, sizes):
    """Calculate capacity estimates"""
    ret = []
    for i, x in enumerate(iats):
        if x == 0 or i == 0:
            pass
        else:
            if sizes[i] == sizes[i - 1]:
                ret.append((8 * sizes[i]) / x)
    return ret
