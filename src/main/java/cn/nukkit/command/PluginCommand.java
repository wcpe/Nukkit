package cn.nukkit.command;

import cn.nukkit.lang.TranslationContainer;
import cn.nukkit.plugin.Plugin;

import java.util.List;

/**
 * author: MagicDroidX
 * Nukkit Project
 */
public class PluginCommand<T extends Plugin> extends Command implements PluginIdentifiableCommand {

    private final T owningPlugin;

    private CommandExecutor executor;
    private TabCompleter completer;


    public PluginCommand(String name, T owner) {
        super(name);
        this.owningPlugin = owner;
        this.executor = owner;
        this.usageMessage = "";
    }

    @Override
    public boolean execute(CommandSender sender, String commandLabel, String[] args) {
        if (!this.owningPlugin.isEnabled()) {
            return false;
        }

        if (!this.testPermission(sender)) {
            return false;
        }

        boolean success = this.executor.onCommand(sender, this, commandLabel, args);

        if (!success && !this.usageMessage.equals("")) {
            sender.sendMessage(new TranslationContainer("commands.generic.usage", this.usageMessage));
        }

        return success;
    }

    public CommandExecutor getExecutor() {
        return executor;
    }

    /**
     * Sets the {@link TabCompleter} to run when tab-completing this command.
     * <p>
     * If no TabCompleter is specified, and the command's executor implements
     * TabCompleter, then the executor will be used for tab completion.
     *
     * @param completer New tab completer
     */
    public void setTabCompleter(TabCompleter completer) {
        this.completer = completer;
    }

    /**
     * Gets the {@link TabCompleter} associated with this command.
     *
     * @return TabCompleter object linked to this command
     */
    public TabCompleter getTabCompleter() {
        return completer;
    }


    public void setExecutor(CommandExecutor executor) {
        this.executor = (executor != null) ? executor : this.owningPlugin;
    }

    @Override
    public T getPlugin() {
        return this.owningPlugin;
    }

     /**
     * {@inheritDoc}
     * <p>
     * Delegates to the tab completer if present.
     * <p>
     * If it is not present or returns null, will delegate to the current
     * command executor if it implements {@link TabCompleter}. If a non-null
     * list has not been found, will default to standard player name
     * completion in {@link
     * Command#tabComplete(CommandSender, String, String[])}.
     * <p>
     * This method does not consider permissions.
     *
     * @throws IllegalArgumentException if sender, alias, or args is null
     */
    @Override
    public java.util.List<String> tabComplete(CommandSender sender, String alias, String[] args) throws IllegalArgumentException {
        List<String> completions = null;
        try {
            if (completer != null) {
                completions = completer.onTabComplete(sender, this, alias, args);
            }
            if (completions == null && executor instanceof TabCompleter) {
                completions = ((TabCompleter) executor).onTabComplete(sender, this, alias, args);
            }
        } catch (Throwable ex) {
            StringBuilder message = new StringBuilder();
            message.append("Unhandled exception during tab completion for command '/").append(alias).append(' ');
            for (String arg : args) {
                message.append(arg).append(' ');
            }
            message.deleteCharAt(message.length() - 1).append("' in plugin ").append(owningPlugin.getDescription().getFullName());
            throw ex;
        }

        if (completions == null) {
            return super.tabComplete(sender, alias, args);
        }
        return completions;
    }
}
