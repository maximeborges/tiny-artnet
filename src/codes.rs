// This is an ArtPoll packet, no other data is contained in this UDP packet.
pub const OP_POLL: u16 = 0x2000;

/// This is an ArtPollReply Packet. It contains device status information.
pub const OP_POLL_REPLY: u16 = 0x2100;

/// Diagnostics and data logging packet.
pub const OP_DIAG_DATA: u16 = 0x2300;

/// Used to send text based parameter commands.
pub const OP_COMMAND: u16 = 0x2400;

/// This is an ArtDmx data packet. It contains zero start code DMX512 information for a single Universe.
pub const OP_OUTPUT: u16 = 0x5000;

/// Alias for [`OP_OUTPUT`]
pub const OP_DMX: u16 = 0x5000;

//This is an ArtNzs data packet. It contains non-zero start code (except RDM) DMX512 information for a single Universe.
pub const OP_NZS: u16 = 0x5100;

/// This is an ArtSync data packet. It is used to force synchronous transfer of ArtDmx packets to a node’s output.
pub const OP_SYNC: u16 = 0x5200;

/// This is an ArtAddress packet. It contains remote programming information for a Node.
pub const OP_ADDRESS: u16 = 0x6000;

/// This is an ArtInput packet. It contains enable – disable data for DMX inputs.
pub const OP_INPUT: u16 = 0x7000;

/// This is an ArtTodRequest packet. It is used to request a Table of Devices (ToD) for RDM discovery.
pub const OP_TOD_REQUEST: u16 = 0x8000;

/// This is an ArtTodData packet. It is used to send a Table of Devices (ToD) for RDM discovery.
pub const OP_TOD_DATA: u16 = 0x8100;

/// This is an ArtTodControl packet. It is used to send RDM discovery control messages.
pub const OP_TOD_CONTROL: u16 = 0x8200;

/// This is an ArtRdm packet. It is used to send all non discovery RDM messages.
pub const OP_RDM: u16 = 0x8300;

/// This is an ArtRdmSub packet. It is used to send compressed, RDM Sub-Device data.
pub const OP_RDM_SUB: u16 = 0x8400;

/// This is an ArtVideoSetup packet. It contains video screen setup information for nodes that implement the extended video features.
pub const OP_VIDEO_SETUP: u16 = 0xa010;

/// This is an ArtVideoPalette packet. It contains colour
/// palette setup information for nodes that implement
/// the extended video features.
pub const OP_VIDEO_PALETTE: u16 = 0xa020;

/// This is an ArtVideoData packet. It contains display data for nodes that implement the extended video features.
pub const OP_VIDEO_DATA: u16 = 0xa040;

/// This packet is deprecated.
pub const OP_MAC_MASTER: u16 = 0xf000;

/// This packet is deprecated.
pub const OP_MAC_SLAVE: u16 = 0xf100;

/// This is an ArtFirmwareMaster packet. It is used to upload new firmware or firmware extensions to the Node.
pub const OP_FIRMWARE_MASTER: u16 = 0xf200;

/// This is an ArtFirmwareReply packet. It is returned by the node to acknowledge receipt of an
/// ArtFirmwareMaster packet or ArtFileTnMaster packet.
pub const OP_FIRMWARE_REPLY: u16 = 0xf300;

/// Uploads user file to node.
pub const OP_FILE_TN_MASTER: u16 = 0xf400;

/// Downloads user file from node.
pub const OP_FILE_FN_MASTER: u16 = 0xf500;

///  Server to Node acknowledge for download packets.
pub const OP_FILE_FN_REPLY: u16 = 0xf600;

///  This is an ArtIpProg packet. It is used to re- programme the IP address and Mask of the Node.
pub const OP_IP_PROG: u16 = 0xf800;

/// This is an ArtIpProgReply packet. It is returned by the node to acknowledge receipt of an ArtIpProg packet.
pub const OP_IP_PROG_REPLY: u16 = 0xf900;

/// This is an ArtMedia packet. It is Unicast by a Media Server and acted upon by a Controller.
pub const OP_MEDIA: u16 = 0x9000;

/// This is an ArtMediaPatch packet. It is Unicast by a Controller and acted upon by a Media Server.
pub const OP_MEDIA_PATCH: u16 = 0x9100;

/// This is an ArtMediaControl packet. It is Unicast by a Controller and acted upon by a Media Server.
pub const OP_MEDIA_CONTROL: u16 = 0x9200;

/// This is an ArtMediaControlReply packet. It is Unicast by a Media Server and acted upon by a Controller.
pub const OP_MEDIA_CONTRL_REPLY: u16 = 0x9300;

/// This is an ArtTimeCode packet. It is used to transport time code over the network.
pub const OP_TIME_CODE: u16 = 0x9700;

/// Used to synchronise real time date and clock
pub const OP_TIME_SYNC: u16 = 0x9800;

/// Used to send trigger macros
pub const OP_TRIGGER: u16 = 0x9900;

/// Requests a node's file list
pub const OP_DIRECTORY: u16 = 0x9a00;

/// Replies to OP_DIRECTORY with file list
pub const OP_DIRECTORY_REPLY: u16 = 0x9b00;
