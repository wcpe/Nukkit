package cn.nukkit.console;

import cn.nukkit.Server;
import cn.nukkit.utils.LogLevel;
import cn.nukkit.utils.WaitRunnable;
import lombok.RequiredArgsConstructor;
import lombok.val;
import org.jline.reader.Candidate;
import org.jline.reader.Completer;
import org.jline.reader.LineReader;
import org.jline.reader.ParsedLine;

import java.util.List;
import java.util.function.Consumer;

@RequiredArgsConstructor
public class NukkitConsoleCompleter implements Completer {
    private final Server server;

    @Override
    public void complete(LineReader lineReader, ParsedLine parsedLine, List<Candidate> candidates) {
        val line = parsedLine.line();
        WaitRunnable<List<String>> waitRunnable = new WaitRunnable<List<String>>() {
            @Override
            protected List<String> evaluate() {
                return server.getCommandMap().tabComplete(server.getConsoleSender(), line);
            }
        };
        server.processQueue.add(waitRunnable);
        try {
            List<String> offers = waitRunnable.get();
            if (offers == null) {
                return;
            }
            for (String offer : offers) {
                candidates.add(new Candidate(offer));
            }

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) {
            this.server.getLogger().log(LogLevel.WARNING, "Tab 补全时出现异常", e);
        }
    }

    private void addCandidates(Consumer<String> commandConsumer) {
        for (String command : server.getCommandMap().getCommands().keySet()) {
            if (!command.contains(":")) {
                commandConsumer.accept(command);
            }
        }
    }
}
