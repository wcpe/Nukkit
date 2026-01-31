package cn.nukkit.entity.custom;

import cn.nukkit.entity.Entity;
import cn.nukkit.level.format.FullChunk;
import cn.nukkit.nbt.tag.CompoundTag;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.BiFunction;

@Getter
public class EntityDefinition {

    public static final AtomicInteger ID_ALLOCATOR = new AtomicInteger(10000);

    private final String identifier;
    private final String parentEntity;
    private final boolean spawnEgg;

    private final String alternateName;
    @Setter
    private BiFunction<FullChunk, CompoundTag, ? extends Entity> entityBiFunction;

    private final boolean serverSideOnly;
    private final int runtimeId;

    private CompoundTag networkTag;

    @Builder
    public EntityDefinition(String identifier, String parentEntity, boolean spawnEgg, String alternateName, boolean serverSideOnly, int runtimeId) {
        // 类型校验转移到 Entity 类的 createEntity 方法下
        //        if (!CustomEntity.class.isAssignableFrom(implementation)) {
//            throw new IllegalArgumentException("Implementation class must implement CustomEntity interface");
//        }

        if (runtimeId == 0 && parentEntity == null) {
            throw new IllegalArgumentException("Server side entity must have parent entity set");
        }

        this.identifier = identifier;
        this.parentEntity = parentEntity;
        this.spawnEgg = spawnEgg;
        this.alternateName = alternateName;
        this.serverSideOnly = serverSideOnly;
        this.runtimeId = runtimeId;

        // SB 老外
//        if (this.serverSideOnly) {
        // 我宣布写出下面这行代码的是纯煞笔
//            int runtimeId = EntityManager.get().getRuntimeId(this.parentEntity);
//            if (runtimeId == 0) {
//                throw new IllegalArgumentException("Unknown entity type " + this.parentEntity);
//            }
//            this.runtimeId = runtimeId;
//        } else {
//            this.runtimeId = ID_ALLOCATOR.getAndIncrement();
//        }
    }

    private CompoundTag createNetworkTag() {
        CompoundTag nbt = new CompoundTag("");
        nbt.putBoolean("hasspawnegg", this.spawnEgg);
        nbt.putBoolean("summonable", true);
        nbt.putString("id", this.identifier);
        nbt.putString("bid", this.parentEntity == null ? "" : this.parentEntity);
        nbt.putInt("rid", this.runtimeId);
        return nbt;
    }

    public CompoundTag getNetworkTag() {
        if (this.networkTag == null) {
            this.networkTag = this.createNetworkTag();
        }
        return this.networkTag;
    }
}
