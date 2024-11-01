package cn.nukkit.command;

import java.util.List;

/**
 * 由 WCPE 在 2024/11/1 14:40 创建
 * <p>
 * Created by WCPE on 2024/11/1 14:40
 * <p>
 * <p>
 * GitHub  : <a href="https://github.com/wcpe">wcpe 's GitHub</a>
 * <p>
 * QQ      : 1837019522
 *
 * @author : WCPE
 */
public interface TabCompleter {

    /**
     * 请求一个命令参数的可能补全列表。
     *
     * @param sender  命令的来源。对于在命令方块内部执行命令的玩家，
     *                该参数将是玩家，而不是命令方块。
     * @param command 执行的命令
     * @param alias   使用的别名
     * @param args    传递给命令的参数，包括最终待补全的部分参数和命令标签
     * @return 一个可能的最终参数补全列表，或返回 null 以默认使用命令执行者
     */
    List<String> onTabComplete(CommandSender sender, Command command, String alias, String[] args);
}
