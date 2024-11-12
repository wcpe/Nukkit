package cn.nukkit.console;

import cn.nukkit.Server;
import cn.nukkit.utils.LogLevel;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.jline.reader.Candidate;
import org.jline.reader.Completer;
import org.jline.reader.LineReader;
import org.jline.reader.ParsedLine;

import java.util.List;

@RequiredArgsConstructor
public class NukkitConsoleCompleter implements Completer {
    private final Server server;

    @Override
    public void complete(LineReader lineReader, ParsedLine parsedLine, List<Candidate> candidates) {
        val line = parsedLine.line();


        try {
            List<String> offers = server.getCommandMap().tabComplete(server.getConsoleSender(), line);
            if (offers == null) {
                return;
            }
            for (String offer : offers) {
                candidates.add(new Candidate(offer));
            }

        } catch (Exception e) {
            this.server.getLogger().log(LogLevel.WARNING, "Unhandled exception when tab completing", e);
        }

    }
}
