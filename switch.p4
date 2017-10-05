#include <core.p4>
#include <v1model.p4>


// constants declaration
const bit<16> ETHERTYPE_IPV4  = 0x0800;
const bit<8>  PROTOCOL_UDP    = 0x11;
const bit<8>  PROTOCOL_TCP    = 0x06;
const bit<8>  PROTOCOL_ICMP   = 0x01;
const bit<5>  IPV4_OPTION_INT = 31;

// compile time definitions
#define MAX_HOPS 9
#define MAX_COUNTERS 10
#define MAX_FLOWS_PER_SWITCH 65536
// 10 seconds in microseconds
#define TIMEOUT_VALUE 1000000
#define CONTROLLER_MIRROR_ID 42

/*************************************************************************
** HEADERS ***************************************************************
*************************************************************************/

// frequently used types
typedef bit<48> macAddr_t;
typedef bit<32> ipv4Addr_t;
typedef bit<16> udpPort_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>     version;
    bit<4>     ihl;
    bit<8>     dscp;
    bit<16>    totalLength;
    bit<16>    identification;
    bit<3>     flags;
    bit<13>    fragmentOffset;
    bit<8>     ttl;
    bit<8>     protocol;
    bit<16>    headerChecksum;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

header ipv4_option_t {
    bit<1> copyFlag;
    bit<2> optionClass;
    bit<5> optionNumber;
    bit<8> optionLength;
}

header int_header_t {
    bit<16> numberOfValues;
}

header int_value_t {
    bit<32> enq_timestamp;
    bit<32> deq_timedelta;
}

header udp_t {
    udpPort_t srcPort;
    udpPort_t dstPort;
    bit<16>   length;
    bit<16>   checksum;
}

// struct to be type H. <v1model.p4> says: H should be a struct of headers or stacks.
struct headers_t {
    ethernet_t            report_ethernet;
    ipv4_t                report_ipv4;
    udp_t                 report_udp;
    ethernet_t            ethernet;
    ipv4_t                ipv4;
    ipv4_option_t         ipv4_option;
    int_header_t          int_header;
    int_value_t[MAX_HOPS] int_values;
}

// HEADER BACKUP STRUCTS
struct ipv4_backup_t {
    bit<4>     ihl;
    bit<16>    totalLength;
    ipv4Addr_t srcAddr;
    ipv4Addr_t dstAddr;
}

struct ipv4_option_backup_t {
    bit<8> optionLength;
}

struct int_header_backup_t {
    bit<16> numberOfValues;
}

struct int_value_backup_t {
    bit<32> enq_timestamp;
    bit<32> deq_timedelta;
}

struct parser_metadata_t {
    bit<16> remaining;
}

// struct to be type M. <v1model.p4> says: M should be a struct of structs.
struct custom_metadata_t {
    // forwarding related
    bit<9> egress_spec;
    // int related
    parser_metadata_t parser_metadata;
    bit<1>  extractAndReportStats;
    bit<4>  insertStat;
    bit<1>  createHeader;
    // backup related
    ipv4_backup_t                backup_ipv4;
    ipv4_option_backup_t         backup_ipv4_option;
    int_header_backup_t          backup_int_header;
    int_value_backup_t           backup_int_values_0;
    int_value_backup_t           backup_int_values_1;
    int_value_backup_t           backup_int_values_2;
    int_value_backup_t           backup_int_values_3;
    int_value_backup_t           backup_int_values_4;
    int_value_backup_t           backup_int_values_5;
    int_value_backup_t           backup_int_values_6;
    int_value_backup_t           backup_int_values_7;
    int_value_backup_t           backup_int_values_8;
}

/*************************************************************************
** PARSER ****************************************************************
*************************************************************************/
error { IPHeaderTooShort }

// parser Parser<H, M>(packet_in P,
//                     out H hs,
//                     inout M cm,
//                     inout standard_metadata_t standard_metadata);
parser packetParser(packet_in p, 
                    out headers_t hs,
                    inout custom_metadata_t cm, 
                    inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        p.extract(hs.ethernet);
        transition select(hs.ethernet.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            default:        accept;
        }
    }

    state parse_ipv4 {
        p.extract(hs.ipv4);
        verify(hs.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hs.ipv4.ihl) {
            5:       accept;
            default: parse_ipv4_option;
        }
    }

    state parse_ipv4_option {
        p.extract(hs.ipv4_option);
        transition select(hs.ipv4_option.optionNumber) {
            IPV4_OPTION_INT: parse_int_header;
            default:         accept;
        }
    }

    state parse_int_header {
        p.extract(hs.int_header);
        cm.parser_metadata.remaining = hs.int_header.numberOfValues;
        transition select(cm.parser_metadata.remaining) {
            0:       accept;
            default: parse_int_value;
        }
    }

    state parse_int_value {
        p.extract(hs.int_values.next);
        cm.parser_metadata.remaining = cm.parser_metadata.remaining - 1;
        transition select(cm.parser_metadata.remaining) {
            0:       accept;
            default: parse_int_value;
        }
    }
}


/*************************************************************************
** VERIFY CHECKSUM *******************************************************
*************************************************************************/
// control VerifyChecksum<H, M>(in H hs,
//                              inout M cm);
control verifyChecksum(in headers_t hs, inout custom_metadata_t cm) {   
    apply { /* intentionally left empty */ }
}

/*************************************************************************
** INGRESS PROCESSING ****************************************************
*************************************************************************/
// @pipeline
// control Ingress<H, M>(inout H hs,
//                       inout M cm,
//                       inout standard_metadata_t sm);
control ingress(inout headers_t hs, 
                inout custom_metadata_t cm, 
                inout standard_metadata_t standard_metadata) {

    action IPv4Forwarding(bit<9> egress_spec) {
        standard_metadata.egress_spec = egress_spec;
        cm.egress_spec = egress_spec;
        hs.ipv4.ttl = hs.ipv4.ttl - 1;
    }

    table ipv4_forwarding {
        key = {
            hs.ipv4.dstAddr: lpm;
        }
        actions = {
            IPv4Forwarding;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if(hs.ipv4.isValid()) {
            ipv4_forwarding.apply();
        }
    }
}

/*************************************************************************
** EGRESS PROCESSING *****************************************************
*************************************************************************/
// control Egress<H, M>(inout H hdr,
//                      inout M meta,
//                      inout standard_metadata_t standard_metadata);
control egress(inout headers_t hs, 
               inout custom_metadata_t cm, 
               inout standard_metadata_t standard_metadata) {

    //****************
    // Header Creation
    //****************
    action createHeader() {
        // increment ipv4 header length field to signal ipv4_option header existance
        // ipv4_option_t + int_header_t = 4 bytes = 32 bits = 1 32-bit word.
        hs.ipv4.ihl = hs.ipv4.ihl + 1;  // ipv4.ihl: number of 32-bit words.
        hs.ipv4.totalLength = hs.ipv4.totalLength + 4;  // ipv4.totalLength: number of bytes.
        // create ipv4_option header
        hs.ipv4_option.setValid();
        hs.ipv4_option.copyFlag = 1;
        hs.ipv4_option.optionClass = 2;  // Debugging and Measurement.
        hs.ipv4_option.optionNumber = IPV4_OPTION_INT;
        hs.ipv4_option.optionLength = 4;  // ipv4_option_t => 2 bytes + int_header_t => 2 bytes
        // create int header
        hs.int_header.setValid();
        hs.int_header.numberOfValues = 0;
    }

    action DoCreateHeader() {
        cm.createHeader = 1;
    }

    action DoNotCreateHeader() {
        cm.createHeader = 0;
    }

    table verify_create_header {
        key = {
            hs.ipv4.srcAddr: exact;
            hs.ipv4.dstAddr: exact;
        }
        actions = {
            DoCreateHeader;
            DoNotCreateHeader;
        }
        default_action = DoNotCreateHeader();
    }

    //*********************
    // Statistics Insertion
    //*********************
    action insertStat() {
        // increment ipv4 header length field
        hs.ipv4.ihl = hs.ipv4.ihl + 2;  // ipv4.ihl: number of 32-bit words.
        hs.ipv4.totalLength = hs.ipv4.totalLength + 8;  // ipv4.totalLength: number of bytes.
        // increment ipv4_option length field
        hs.ipv4_option.optionLength = hs.ipv4_option.optionLength + 8;
        // increment int_header value counter
        hs.int_header.numberOfValues = hs.int_header.numberOfValues + 1;
        // insert new int_value
        hs.int_values.push_front(1);
        hs.int_values[0].enq_timestamp = standard_metadata.enq_timestamp;
        hs.int_values[0].deq_timedelta = (bit<32>) standard_metadata.enq_qdepth;
    }

    action DoInsertStat(bit<4> K) {
        cm.insertStat = K;
    }

    action DoNotInsertStat() {
        cm.insertStat = 0;
    }

    table verify_insert_stat {
        key = {
            hs.ipv4.srcAddr: exact;
            hs.ipv4.dstAddr: exact;
        }
        actions = {
            DoInsertStat;
            DoNotInsertStat;
        }
        default_action = DoNotInsertStat();
    }

    //********************************
    // Header Extraction and Reporting
    //********************************
    action BuildReportHeaders(macAddr_t ethernet_src, macAddr_t ethernet_dst, 
                              udpPort_t udp_src, udpPort_t udp_dst) {
        hs.report_udp.setValid();
        hs.report_udp.srcPort = udp_src;
        hs.report_udp.dstPort = udp_dst;
        hs.report_udp.length = (8 + cm.backup_ipv4.totalLength - (((bit<16>)cm.backup_ipv4.ihl)*4));
        hs.report_udp.checksum = 0;  // optional for ipv4
        hs.report_ipv4.setValid();
        hs.report_ipv4.version = 4;
        hs.report_ipv4.ihl = cm.backup_ipv4.ihl;  // 32-bit word length
        hs.report_ipv4.dscp = 0;
        hs.report_ipv4.totalLength = cm.backup_ipv4.totalLength + 8;
        hs.report_ipv4.identification = 2;
        hs.report_ipv4.flags = 0;
        hs.report_ipv4.fragmentOffset = 0;
        hs.report_ipv4.ttl = 64;
        hs.report_ipv4.protocol = 17;
        hs.report_ipv4.headerChecksum = 0;  // will be set on actual egress
        hs.report_ipv4.srcAddr = cm.backup_ipv4.srcAddr;
        hs.report_ipv4.dstAddr = cm.backup_ipv4.dstAddr;
        hs.report_ethernet.setValid();
        hs.report_ethernet.dstAddr = ethernet_dst;
        hs.report_ethernet.srcAddr = ethernet_src;
        hs.report_ethernet.etherType = ETHERTYPE_IPV4;        
    }

    table build_report_headers {
        actions = {
            BuildReportHeaders;
            NoAction;
        }
        default_action = NoAction();
    }
    
    action DoExtractAndReportStats() {
        cm.extractAndReportStats = 1;
    }

    action DoNotExtractAndReportStats() {
        cm.extractAndReportStats = 0;
    }

    table verify_extract_and_report_stats {
        key = {
            hs.ipv4.srcAddr: exact;
            hs.ipv4.dstAddr: exact;
        }
        actions = {
            DoExtractAndReportStats;
            DoNotExtractAndReportStats;
        }
        default_action = DoNotExtractAndReportStats();
    }

    //********************
    // Ethernet Addressing
    //********************
    action setEthernetAddresses(macAddr_t srcAddr, macAddr_t dstAddr) {
        hs.ethernet.srcAddr = srcAddr;
        hs.ethernet.dstAddr = dstAddr;
    }

    table set_ethernet_addresses {
        key = {
            standard_metadata.egress_port : exact;
        }
        actions = {
            setEthernetAddresses;
            NoAction;
        }
        default_action = NoAction();
    }

    //*********************
    // Pipepline Apply Body
    //*********************
    apply {
        if(hs.ipv4.isValid()) {
            if((hs.ipv4.protocol != PROTOCOL_UDP) 
               && (hs.ipv4.protocol != PROTOCOL_TCP)
               && (hs.ipv4.protocol != PROTOCOL_ICMP)
               && (standard_metadata.instance_type == 0)
              ) {
                set_ethernet_addresses.apply();
            } else if((hs.ipv4.protocol == PROTOCOL_UDP)
                      || (hs.ipv4.protocol == PROTOCOL_TCP)
                      || (hs.ipv4.protocol == PROTOCOL_ICMP)) {
                if(standard_metadata.instance_type == 0) {  // Packet is not a clone.
                    // Modify ethernet addresses
                    set_ethernet_addresses.apply();

                    verify_create_header.apply();
                    verify_insert_stat.apply();
                    verify_extract_and_report_stats.apply();

                    if (cm.createHeader == 1) {
                        createHeader();
                    }

                    if (cm.insertStat != 0) {
                        if (1 <= cm.insertStat) {
                            insertStat();
                        }
                        if (2 <= cm.insertStat) {
                            insertStat();
                        }
                        if (3 <= cm.insertStat) {
                            insertStat();
                        }
                        if (4 <= cm.insertStat) {
                            insertStat();
                        }
                        if (5 <= cm.insertStat) {
                            insertStat();
                        }
                        if (6 <= cm.insertStat) {
                            insertStat();
                        }
                        if (7 <= cm.insertStat) {
                            insertStat();
                        }
                        if (8 <= cm.insertStat) {
                            insertStat();
                        }
                        if (9 <= cm.insertStat) {
                            insertStat();
                        }

                    }

                    if (cm.extractAndReportStats == 1) {
                        cm.backup_ipv4.ihl = hs.ipv4.ihl;
                        cm.backup_ipv4.totalLength = hs.ipv4.totalLength;
                        cm.backup_ipv4.srcAddr = hs.ipv4.srcAddr;
                        cm.backup_ipv4.dstAddr = hs.ipv4.dstAddr;
                        /*************************************************************************
                        ** SAVE AND REMOVE INT ***************************************************
                        *************************************************************************/
                        // ******* ipv4 *******
                        // save
                        cm.backup_ipv4.ihl = hs.ipv4.ihl;
                        cm.backup_ipv4.totalLength = hs.ipv4.totalLength;
                        // remove INT
                        hs.ipv4.totalLength = (hs.ipv4.totalLength
                                               - (((bit<16>)(hs.ipv4.ihl) - 5) * 4));
                        hs.ipv4.ihl = 5;
                        // ******* ipv4_option *******
                        // save
                        cm.backup_ipv4_option.optionLength = hs.ipv4_option.optionLength;
                        // remove INT
                        hs.ipv4_option.setInvalid();
                        // ******* int_header *******
                        // save
                        cm.backup_int_header.numberOfValues = hs.int_header.numberOfValues;
                        // remove INT
                        hs.int_header.setInvalid();
                        // ******* int_value(s) *******
                        if(1 <= cm.backup_int_header.numberOfValues) {
                            cm.backup_int_values_0.enq_timestamp = hs.int_values[0].enq_timestamp;
                            cm.backup_int_values_0.deq_timedelta = hs.int_values[0].deq_timedelta;
                            hs.int_values[0].setInvalid();
                        }
                        if(2 <= cm.backup_int_header.numberOfValues) {
                            cm.backup_int_values_1.enq_timestamp = hs.int_values[1].enq_timestamp;
                            cm.backup_int_values_1.deq_timedelta = hs.int_values[1].deq_timedelta;
                            hs.int_values[1].setInvalid();
                        }
                        if(3 <= cm.backup_int_header.numberOfValues) {
                            cm.backup_int_values_2.enq_timestamp = hs.int_values[2].enq_timestamp;
                            cm.backup_int_values_2.deq_timedelta = hs.int_values[2].deq_timedelta;
                            hs.int_values[2].setInvalid();
                        }
                        if(4 <= cm.backup_int_header.numberOfValues) {
                            cm.backup_int_values_3.enq_timestamp = hs.int_values[3].enq_timestamp;
                            cm.backup_int_values_3.deq_timedelta = hs.int_values[3].deq_timedelta;
                            hs.int_values[3].setInvalid();
                        }
                        if(5 <= cm.backup_int_header.numberOfValues) {
                            cm.backup_int_values_4.enq_timestamp = hs.int_values[4].enq_timestamp;
                            cm.backup_int_values_4.deq_timedelta = hs.int_values[4].deq_timedelta;
                            hs.int_values[4].setInvalid();
                        }
                        if(6 <= cm.backup_int_header.numberOfValues) {
                            cm.backup_int_values_5.enq_timestamp = hs.int_values[5].enq_timestamp;
                            cm.backup_int_values_5.deq_timedelta = hs.int_values[5].deq_timedelta;
                            hs.int_values[5].setInvalid();
                        }
                        if(7 <= cm.backup_int_header.numberOfValues) {
                            cm.backup_int_values_6.enq_timestamp = hs.int_values[6].enq_timestamp;
                            cm.backup_int_values_6.deq_timedelta = hs.int_values[6].deq_timedelta;
                            hs.int_values[6].setInvalid();
                        }
                        if(8 <= cm.backup_int_header.numberOfValues) {
                            cm.backup_int_values_7.enq_timestamp = hs.int_values[7].enq_timestamp;
                            cm.backup_int_values_7.deq_timedelta = hs.int_values[7].deq_timedelta;
                            hs.int_values[7].setInvalid();
                        }
                        if(9 <= cm.backup_int_header.numberOfValues) {
                            cm.backup_int_values_8.enq_timestamp = hs.int_values[8].enq_timestamp;
                            cm.backup_int_values_8.deq_timedelta = hs.int_values[8].deq_timedelta;
                            hs.int_values[8].setInvalid();
                        }
                        // Clone packet to send a report to the controller (h1).
                        clone3(CloneType.E2E, CONTROLLER_MIRROR_ID, {cm});
                    }

                } else if(standard_metadata.instance_type == 2) { // Packet is an egress to egress clone.
                    build_report_headers.apply();
                    // remove ethernet and ipv4 headers
                    hs.ethernet.setInvalid();
                    hs.ipv4.setInvalid();
                    /*************************************************************************
                    ** REBUILD INT ***********************************************************
                    *************************************************************************/
                    // ******* ipv4_option *******
                    hs.ipv4_option.setValid();
                    hs.ipv4_option.copyFlag = 1;
                    hs.ipv4_option.optionClass = 2;
                    hs.ipv4_option.optionNumber = IPV4_OPTION_INT;
                    hs.ipv4_option.optionLength = cm.backup_ipv4_option.optionLength;
                    // ******* int_header *******
                    hs.int_header.setValid();
                    hs.int_header.numberOfValues = cm.backup_int_header.numberOfValues;
                    // ******* int_value(s) *******
                    if(1 <= cm.backup_int_header.numberOfValues) {
                        hs.int_values[0].setValid();
                        hs.int_values[0].enq_timestamp = cm.backup_int_values_0.enq_timestamp;
                        hs.int_values[0].deq_timedelta = cm.backup_int_values_0.deq_timedelta;
                    }
                    if(2 <= cm.backup_int_header.numberOfValues) {
                        hs.int_values[1].setValid();
                        hs.int_values[1].enq_timestamp = cm.backup_int_values_1.enq_timestamp;
                        hs.int_values[1].deq_timedelta = cm.backup_int_values_1.deq_timedelta;
                    }
                    if(3 <= cm.backup_int_header.numberOfValues) {
                        hs.int_values[2].setValid();
                        hs.int_values[2].enq_timestamp = cm.backup_int_values_2.enq_timestamp;
                        hs.int_values[2].deq_timedelta = cm.backup_int_values_2.deq_timedelta;
                    }
                    if(4 <= cm.backup_int_header.numberOfValues) {
                        hs.int_values[3].setValid();
                        hs.int_values[3].enq_timestamp = cm.backup_int_values_3.enq_timestamp;
                        hs.int_values[3].deq_timedelta = cm.backup_int_values_3.deq_timedelta;
                    }
                    if(5 <= cm.backup_int_header.numberOfValues) {
                        hs.int_values[4].setValid();
                        hs.int_values[4].enq_timestamp = cm.backup_int_values_4.enq_timestamp;
                        hs.int_values[4].deq_timedelta = cm.backup_int_values_4.deq_timedelta;
                    }
                    if(6 <= cm.backup_int_header.numberOfValues) {
                        hs.int_values[5].setValid();
                        hs.int_values[5].enq_timestamp = cm.backup_int_values_5.enq_timestamp;
                        hs.int_values[5].deq_timedelta = cm.backup_int_values_5.deq_timedelta;
                    }
                    if(7 <= cm.backup_int_header.numberOfValues) {
                        hs.int_values[6].setValid();
                        hs.int_values[6].enq_timestamp = cm.backup_int_values_6.enq_timestamp;
                        hs.int_values[6].deq_timedelta = cm.backup_int_values_6.deq_timedelta;
                    }
                    if(8 <= cm.backup_int_header.numberOfValues) {
                        hs.int_values[7].setValid();
                        hs.int_values[7].enq_timestamp = cm.backup_int_values_7.enq_timestamp;
                        hs.int_values[7].deq_timedelta = cm.backup_int_values_7.deq_timedelta;
                    }
                    if(9 <= cm.backup_int_header.numberOfValues) {
                        hs.int_values[8].setValid();
                        hs.int_values[8].enq_timestamp = cm.backup_int_values_8.enq_timestamp;
                        hs.int_values[8].deq_timedelta = cm.backup_int_values_8.deq_timedelta;
                    }
                }
            }
        }
    }
}

/*************************************************************************
** COMPUTE CHECKSUM ******************************************************
*************************************************************************/
// control ComputeChecksum<H, M>(inout H hs,
//                               inout M cm);
control computeChecksum(inout headers_t  hs,
                        inout custom_metadata_t cm) {
    Checksum16() ipv4_checksum;
    
    apply {
        if (hs.report_ipv4.isValid()) {
            hs.report_ipv4.headerChecksum = ipv4_checksum.get(
            {    
                hs.report_ipv4.version,
                hs.report_ipv4.ihl,
                hs.report_ipv4.dscp,
                hs.report_ipv4.totalLength,
                hs.report_ipv4.identification,
                hs.report_ipv4.flags,
                hs.report_ipv4.fragmentOffset,
                hs.report_ipv4.ttl,
                hs.report_ipv4.protocol,
                hs.report_ipv4.srcAddr,
                hs.report_ipv4.dstAddr
            });
        }

        if (hs.ipv4.isValid()) {
            hs.ipv4.headerChecksum = ipv4_checksum.get(
            {    
                hs.ipv4.version,
                hs.ipv4.ihl,
                hs.ipv4.dscp,
                hs.ipv4.totalLength,
                hs.ipv4.identification,
                hs.ipv4.flags,
                hs.ipv4.fragmentOffset,
                hs.ipv4.ttl,
                hs.ipv4.protocol,
                hs.ipv4.srcAddr,
                hs.ipv4.dstAddr
            });
        }
    }
}

/*************************************************************************
** DEPARSER **************************************************************
*************************************************************************/
// @deparser
// control Deparser<H>(packet_out p, in H hs);
control packetDeparser(packet_out p, in headers_t hs) {
    apply {
        p.emit(hs.report_ethernet);
        p.emit(hs.report_ipv4);
        p.emit(hs.ethernet);
        p.emit(hs.ipv4);
        p.emit(hs.ipv4_option);
        p.emit(hs.int_header);
        p.emit(hs.int_values);                 
        p.emit(hs.report_udp);
    }
}

/*************************************************************************
** SWITCH ****************************************************************
*************************************************************************/
V1Switch (
    packetParser(),
    verifyChecksum(),
    ingress(),
    egress(),
    computeChecksum(),
    packetDeparser()
) main;
