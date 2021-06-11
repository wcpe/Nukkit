package cn.nukkit.level;

import cn.nukkit.Server;
import com.google.common.io.ByteStreams;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import it.unimi.dsi.fastutil.ints.Int2IntMap;
import it.unimi.dsi.fastutil.ints.Int2IntOpenHashMap;
import lombok.extern.log4j.Log4j2;

import java.io.*;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.concurrent.atomic.AtomicInteger;

@Log4j2
public class GlobalBlockPalette {
    private static final Int2IntMap legacyToRuntimeId = new Int2IntOpenHashMap();
//    private static final Int2IntMap runtimeIdToLegacy = new Int2IntOpenHashMap();
    private static final AtomicInteger runtimeIdAllocator = new AtomicInteger(0);

    static {
        legacyToRuntimeId.defaultReturnValue(-1);
//        runtimeIdToLegacy.defaultReturnValue(-1);

        Gson gson = new Gson();
        Type collectionType = new TypeToken<Collection<TableEntry>>() {
        }.getType();

        Collection<TableEntry> entries;
        try (InputStream stream = Server.class.getClassLoader().getResourceAsStream("runtime_block_ids.json")) {
            if (stream == null) {
                throw new AssertionError("Unable to locate runtime_block_ids.json");
            }
            try (Reader reader = new InputStreamReader(new ByteArrayInputStream(ByteStreams.toByteArray(stream)), StandardCharsets.UTF_8)) {
                entries = gson.fromJson(reader, collectionType);
            }
        } catch (IOException e) {
            throw new AssertionError("Unable to load block palette", e);
        }

        int nextRuntimeId = 0;
        for (TableEntry entry : entries) {
            int legacyId = (entry.blockId << 14) | entry.meta;
            int runtimeId = entry.runTimeId;
//            runtimeIdToLegacy.put(runtimeId, legacyId);
            legacyToRuntimeId.put(legacyId, runtimeId);

            if (nextRuntimeId <= runtimeId) {
                nextRuntimeId = runtimeId + 1;
            }
        }

        runtimeIdAllocator.set(nextRuntimeId);
    }

    public static int getOrCreateRuntimeId(int id, int meta) {
        int legacyIdNoMeta = id << 14;
        int legacyId = legacyIdNoMeta | meta;
        int runtimeId = legacyToRuntimeId.get(legacyId);
        if (runtimeId == -1) {
            runtimeId = legacyToRuntimeId.get(legacyIdNoMeta);
            if (runtimeId == -1) {
                log.info("Creating new runtime ID for unknown block {}", id);
                runtimeId = runtimeIdAllocator.getAndIncrement();
                legacyToRuntimeId.put(legacyIdNoMeta, runtimeId);
//                runtimeIdToLegacy.put(runtimeId, legacyIdNoMeta);
            }
        }
        return runtimeId;
    }

    public static int getOrCreateRuntimeId(int legacyId) {
        return getOrCreateRuntimeId(legacyId >> 4, legacyId & 0xf);
    }

    private static class TableEntry {
        private int runTimeId;
        private int blockId;
        private int meta;
        private String blockName;
    }
}
