import json
import sys
from argument_parser import parser_data_gathering

SAVECACHE = False
USEWHOISDATA = False

timeIDSInCapture = []
result = {}
temp = {}
connectionCache = {}


def load_computers_to_analyze_from_file(parameters):
    return parameters.ip


def intialize_computers_to_analyze(ips):
    for ip in ips:
        result[ip] = {}
        result[ip]['time'] = {}
        result[ip]['perflow'] = {}
        result[ip]['perflow']['consumerproducerratio'] = set()
        temp[ip] = {}
    for ip in temp:
        initializeTempHourDict(temp[ip])


def fill_features_class_from_temp_class(time):
    if not time:
        return
    dataDateID = time.split(' ')[0]
    dataHourID = time.split(' ')[1] + ' ' + time.split(' ')[2]

    for ip in result:

        ipfeaturesTimeDict = temp[ip]
        temp[ip] = {}

        ipfeaturesTimeDict['hoursummary']['clientNumberOfConnectionsNotEstablished'] = len(
            ipfeaturesTimeDict['clientDictOfConnectionsNotEstablished'])
        ipfeaturesTimeDict['hoursummary']['serverNumberOfConnectionsNotEstablished'] = len(
            ipfeaturesTimeDict['serverDictOfConnectionsNotEstablished'])

        ipfeaturesTimeDict['hoursummary']['clientNumberOfDistinctCountriesEstablished'] = len(
            ipfeaturesTimeDict['clientDictNumberOfDistinctCountriesEstablished'])
        ipfeaturesTimeDict['hoursummary']['clientNumberOfDistinctOrganizationsEstablished'] = len(
            ipfeaturesTimeDict['clientDictNumberOfDistinctOrganizationsEstablished'])

        if dataDateID in result[ip]['time']:
            result[ip]['time'][dataDateID][dataHourID] = ipfeaturesTimeDict
        else:
            result[ip]['time'][dataDateID] = {}
            result[ip]['time'][dataDateID][dataHourID] = ipfeaturesTimeDict


def initializeTempHourDict(temp_dect):
    temp_dect['hoursummary'] = {}
    temp_dect['hoursummary']['numberOfIPFlows'] = 0

    initializeNumberFeatureAsServerAsClient(temp_dect['hoursummary'], 'NumberOfIPFlows')
    initializeNumberFeatureAsServerAsClient(temp_dect['hoursummary'], 'TotalNumberOfTransferedData')

    initializeDictFeatureAsServerAsClient(temp_dect, 'DictOfConnections')
    initializeDictFeatureAsServerAsClient(temp_dect, 'DictNumberOfDistinctCountries')
    initializeDictFeatureAsServerAsClient(temp_dect, 'DictNumberOfDistinctOrganizations')
    initializeDictFeatureAsServerAsClient(temp_dect, 'DictClassBnetworks')

    initializeDictFeatureAsServerAsClient(temp_dect, 'PAPAconections')

    initializePortFeatures(temp_dect)

    initializeDictFeatureAsServerAsClient(temp_dect, 'DestinationPortDictIPsTCP')
    initializeDictFeatureAsServerAsClient(temp_dect, 'DestinationPortDictIPsUDP')


def initializeDictFeatureAsServerAsClient(dict, name):
    dict['client' + name + 'Established'] = {}
    dict['client' + name + 'NotEstablished'] = {}

    dict['server' + name + 'Established'] = {}
    dict['server' + name + 'NotEstablished'] = {}


def initializeNumberFeatureAsServerAsClient(dict, name):
    dict['client' + name + 'Established'] = 0
    dict['client' + name + 'NotEstablished'] = 0

    dict['server' + name + 'Established'] = 0
    dict['server' + name + 'NotEstablished'] = 0


def processLine(line_dict, last_time_id, time_window=5):
    time = line_dict['StartTime']
    data_date_id = time.split()[0]
    data_hour_id = time.split()[1].split(':')[0]
    data_min_id = time.split()[1].split(':')[1]
    data_hour_id = f'{data_hour_id} {int(data_min_id)//(time_window)}'
    # data_hour_id = data_hour_id + ' ' + str(int(dataMinID) / time_window)
    actual_data_id = data_date_id + ' ' + data_hour_id + ' ' + str(int(data_min_id) // time_window)
    if actual_data_id != last_time_id:
        # print(data_hour_id)
        timeIDSInCapture.append(data_hour_id)
        fill_features_class_from_temp_class(last_time_id)
        for ip in temp:
            initializeTempHourDict(temp[ip])

    dur = line_dict['Dur']
    protocol = line_dict['Proto']
    ip_from = line_dict['SrcAddr']
    source_port = line_dict['Sport']
    ip_to = line_dict['DstAddr']
    dst_port = line_dict['Dport']
    connection_information_state = line_dict['State']
    total_pakets = float(line_dict['TotPkts'])
    tot_bytes = float(line_dict['TotBytes'])
    src_bytes = float(line_dict['SrcBytes'])

    if ip_from in result:
        addFeaturesForIP('client', ip_from, ip_to, line_dict, dur, protocol, source_port, dst_port,
                         connection_information_state, total_pakets, tot_bytes, src_bytes)
    if ip_to in result:
        addFeaturesForIP('server', ip_to, ip_from, line_dict, dur, protocol, source_port, dst_port,
                         connection_information_state, total_pakets, tot_bytes, src_bytes)

    # TODO deal with _RA
    # print (line)
    return actual_data_id


# ipDict is ip where the features are added
def addFeaturesForIP(clientorserver, ipDict, ipTarget, lineDict, dur, protocol, sourcePort, dstPort,
                     connectionInformationState, totalPakets, totBytes, srcBytes):
    ipFeaturesTemp = temp[ipDict]
    ipFeaturesTemp['hoursummary'][clientorserver + 'NumberOfIPFlowsEstablished'] = ipFeaturesTemp['hoursummary'][
                                                                                       clientorserver + 'NumberOfIPFlowsEstablished'] + 1
    # ipFeaturesTemp['hoursummary']['numberOfIPFlows'] = ipFeaturesTemp['hoursummary']['numberOfIPFlows'] + 1
    # per flow consumer/producer ratio
    result[ipDict]['perflow']['consumerproducerratio'].add(srcBytes / totBytes)
    if detectConnection(connectionInformationState):
        # ipFeaturesTemp['clientDictIPSContacted'].add (ipTo)
        # addFeaturesToDict (ipFeaturesTemp, 'clientDictIPSContacted', ipTarget, 1)


        classB = ipTarget.split('.')[0] + '.' + ipTarget.split('.')[1]
        addFeaturesToDict(ipFeaturesTemp, clientorserver + 'DictClassBnetworksEstablished', classB, 1)
        ipFeaturesTemp['hoursummary'][clientorserver + 'TotalNumberOfTransferedDataEstablished'] = \
            ipFeaturesTemp['hoursummary'][
                clientorserver + 'TotalNumberOfTransferedDataEstablished'] + totBytes
        fillDataToPortFeatures(clientorserver, protocol, ipFeaturesTemp, dstPort, ipTarget, sourcePort, totBytes,
                               totalPakets, lineDict, 'Established')
    elif detectConnectionAttemptWithNoAnswer(connectionInformationState):
        addFeaturesToDict(ipFeaturesTemp, clientorserver + 'DictOfConnectionsNotEstablished', ipTarget, 1)
        # TODO Ask sebas if not answered connections should be in the histograms, make the two colors mode for this
        fillDataToPortFeatures(clientorserver, protocol, ipFeaturesTemp, dstPort, ipTarget, sourcePort, totBytes,
                               totalPakets, lineDict, 'NotEstablished')
        # TODO Check log of not used lines that should be catched by this


    elif detectPAPAsituation(connectionInformationState):
        if detectEndingConection(connectionInformationState):
            # print "Connection ended"
            pass
        else:
            if ipTarget in ipFeaturesTemp[clientorserver + 'PAPAconectionsEstablished']:
                ipFeaturesTemp[clientorserver + 'PAPAconectionsEstablished'][ipTarget] += 1
            else:
                ipFeaturesTemp[clientorserver + 'PAPAconectionsEstablished'][ipTarget] = 1
    else:
        pass
        # print(convertDictToLine(lineDict))

    ipFeaturesTemp['hoursummary']['numberOfIPFlows'] = ipFeaturesTemp['hoursummary']['numberOfIPFlows'] + 1


def unusedSnippedsOfCode():
    # value = ipFeaturesTemp['clientDestinationPortNumberOfFlowsTCP'].get (sourcePort, None)
    # if value is not None:
    #     ipFeaturesTemp["clientDestinationPortNumberOfFlowsTCP"][sourcePort] += 1
    # else:
    #     ipFeaturesTemp["clientDestinationPortNumberOfFlowsTCP"][sourcePort] = 1
    print('not used anymore')


def initializePortFeatures(tempDict):
    s = ['client', 'server']
    d = ['SourcePort', 'DestinationPort']
    f = ['TotalBytes', 'TotalPackets', 'NumberOfFlows']
    p = ['TCP', 'UDP']
    e = ['Established', 'NotEstablished']
    for source in s:
        for port in d:
            for feature in f:
                for protocol in p:
                    for established in e:
                        tempDict[source + port + feature + protocol + established] = {}


def fillDataToPortFeatures(clientorserver, protocol, ipFeaturesTemp, dstPort, ipTarget, sourcePort, totBytes,
                           totalPakets, lineDict, answeredornot):
    if clientorserver == 'client':
        portDictIPS = 'clientDestinationPortDictIPs'
    else:
        portDictIPS = 'serverDestinationPortDictIPs'

    if protocol == 'tcp':
        addPortDictIPSToDict(ipFeaturesTemp, portDictIPS + 'TCP' + answeredornot, dstPort, ipTarget)
        addAllPortFeaturesToDict(ipFeaturesTemp, clientorserver, protocol, sourcePort, dstPort, totBytes, totalPakets,
                                 answeredornot)
    elif protocol == 'udp':  # udp protocol
        addPortDictIPSToDict(ipFeaturesTemp, portDictIPS + 'UDP' + answeredornot, dstPort, ipTarget)
        addAllPortFeaturesToDict(ipFeaturesTemp, clientorserver, protocol, sourcePort, dstPort, totBytes, totalPakets,
                                 answeredornot)
    else:
        pass
        # print(convertDictToLine(lineDict))


def addAllPortFeaturesToDict(ipFeaturesTemp, source, protocol, sourcePort, destinationPort, totalBytes, totalPackets,
                             answeredornot):
    d = {'SourcePort': sourcePort, 'DestinationPort': destinationPort}
    f = {'TotalBytes': totalBytes, 'TotalPackets': totalPackets, 'NumberOfFlows': 1}
    for port in d:
        for feature in f:
            nameOfTheFeauture = source + port + feature + protocol.upper() + answeredornot
            addFeaturesToDict(ipFeaturesTemp, nameOfTheFeauture, d[port], f[feature])


def addFeaturesToDict(ipFeaturesTemp, dictname, data, howmuchadd):
    if data in ipFeaturesTemp[dictname]:
        ipFeaturesTemp[dictname][data] += howmuchadd
    else:
        ipFeaturesTemp[dictname][data] = howmuchadd


def addPortDictIPSToDict(ipFeaturesTemp, dictname, port, ip):
    if port in ipFeaturesTemp[dictname]:
        if ip in ipFeaturesTemp[dictname][port]:
            ipFeaturesTemp[dictname][port][ip] += 1
        else:
            ipFeaturesTemp[dictname][port][ip] = 1
    else:
        ipFeaturesTemp[dictname][port] = {ip: 1}


def detectConnection(connectionInformation):
    # TODO : For the UDP
    if (connectionInformation == 'CON') or (connectionInformation == 'EST'):  # CON and EST for TCP, CON for UDP
        return True
    # if (connectionInformation == 'URP'):    #ASK SEBAS FOR THIS, this is icmp protocol
    #    return True
    if len(connectionInformation.split('_')) != 2:
        return False
    connectionInformationFrom = connectionInformation.split('_')[0]
    connectionInformationTo = connectionInformation.split('_')[1]
    if (
            'S' in connectionInformationFrom and 'S' in connectionInformationTo and 'A' in connectionInformationTo):  # maybe add to the dict of opened connection if there is no fin
        return True
    return False


def detectConnectionAttemptWithNoAnswer(connectionInformation):
    if connectionInformation == 'REQ' or connectionInformation == 'INT':  # for UDP
        return True
    if len(connectionInformation.split('_')) != 2:
        return False
    # for TCP
    connectionInformationFrom = connectionInformation.split('_')[0]
    connectionInformationTo = connectionInformation.split('_')[1]
    if ('S' in connectionInformationFrom and connectionInformationTo == ''):  # Absolutely no answer
        return True
    if (
            'S' in connectionInformationFrom and 'R' in connectionInformationTo and 'A' in connectionInformationTo):  # Reset Acknowledged
        return True
    return False


def detectPAPAsituation(connectionInformation):
    if len(connectionInformation.split('_')) != 2:
        return False
    connectionInformationFrom = connectionInformation.split('_')[0]
    connectionInformationTo = connectionInformation.split('_')[1]
    if ('A' in connectionInformationFrom) and ('A' in connectionInformationTo):
        return True
    return False


def detectEndingConection(connectionInformation):
    if len(connectionInformation.split('_')) != 2:
        return False
    connectionInformationFrom = connectionInformation.split('_')[0]
    connectionInformationTo = connectionInformation.split('_')[1]
    if (('F' in connectionInformationFrom)
            or ('F' in connectionInformationTo)
            or ('R' in connectionInformationFrom)
            or ('R' in connectionInformationTo)):
        return True
    return False


def stripSpacesFromConnection(string):
    string.lstrip(' ')
    string = string[2:]
    whitelist = set('<->')
    ''.join(filter(whitelist.__contains__, string))
    whitelist = set('->')
    ''.join(filter(whitelist.__contains__, string))
    return string


def convertLineToDict(line):
    # StartTime, Dur, Proto, SrcAddr, Sport, Dir, DstAddr, Dport, State, sTos, dTos, TotPkts, TotBytes, SrcBytes, Label
    lineDict = {}
    components = line.split(',')
    lineDict['StartTime'] = components[0]
    lineDict['Dur'] = components[1]
    lineDict['Proto'] = components[2]
    lineDict['SrcAddr'] = components[3]
    lineDict['Sport'] = components[4]
    lineDict['Dir'] = components[5]
    lineDict['DstAddr'] = components[6]
    lineDict['Dport'] = components[7]
    lineDict['State'] = components[8]
    lineDict['sTos'] = components[9]
    lineDict['dTos'] = components[10]
    lineDict['TotPkts'] = components[11]
    lineDict['TotBytes'] = components[12]
    lineDict['SrcBytes'] = components[13]
    lineDict['Label'] = components[14]
    return lineDict


def convertDictToLine(lineDict):
    return lineDict['StartTime'] + ',' + lineDict['Dur'] + ',' + lineDict['Proto'] + ',' + lineDict['SrcAddr'] + ',' + \
           lineDict['Sport'] + ',' + lineDict['Dir'] + ',' + lineDict['DstAddr'] + ',' + lineDict['Dport'] + ',' + \
           lineDict['State'] + ',' + lineDict['sTos'] + ',' + lineDict['dTos'] + ',' + lineDict['TotPkts'] + ',' + \
           lineDict['TotBytes'] + ',' + lineDict['SrcBytes'] + ',' + lineDict['Label']


def gatherData(train_file):
    with open(train_file, 'r') as f:
        next(f)
        lastHourID = ""
        for line in f:
            lineDict = convertLineToDict(line)
            lastHourID = processLine(lineDict, lastHourID)
        fill_features_class_from_temp_class(lastHourID)


def getTimeIDSInCapture():
    return timeIDSInCapture


def getResult():
    return result


def dumper(obj):
    if isinstance(obj, set):
        return list(obj)
    return obj.__dict__


def humanreadabledump(obj):
    if isinstance(obj, set):
        return str(list(obj))
        # return ','.join(filter(None, list (obj)))
    return obj.__dict__


if __name__ == "__main__":
    parameters = parser_data_gathering.parse_args(sys.argv[1:])

    ips = load_computers_to_analyze_from_file(parameters)
    intialize_computers_to_analyze(ips)
    gatherData(parameters.train_file)

    print('printed lines are not taken in account for profile, my TODO is to include them all')
    print('saving results')
    with open(parameters.file, 'w') as fp:
        json.dump(result, fp, default=dumper)
    print('done')
