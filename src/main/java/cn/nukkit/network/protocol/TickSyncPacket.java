package cn.nukkit.network.protocol;

import lombok.ToString;

@ToString
public class TickSyncPacket extends DataPacket {

    public static final byte NETWORK_ID = ProtocolInfo.TICK_SYNC_PACKET;

    public long clientSendTime;
    public long serverReceiveTime;

    @Override
    public byte pid() {
        return NETWORK_ID;
    }

    @Override
    public void decode() {
        this.clientSendTime = this.getLLong();
        this.serverReceiveTime = this.getLLong();
    }

    @Override
    public void encode() {
        this.reset();
        this.putLLong(this.clientSendTime);
        this.putLLong(this.serverReceiveTime);
    }
}
