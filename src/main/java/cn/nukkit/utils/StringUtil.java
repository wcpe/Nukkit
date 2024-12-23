package cn.nukkit.utils;

/**
 * 由 WCPE 在 2024/11/1 14:33 创建
 * <p>
 * Created by WCPE on 2024/11/1 14:33
 * <p>
 * <p>
 * GitHub  : <a href="https://github.com/wcpe">wcpe 's GitHub</a>
 * <p>
 * QQ      : 1837019522
 *
 * @author : WCPE
 */
public class StringUtil {


    /**
     * 该方法使用区域匹配来检查忽略大小写的相等性。这意味着内部数组不需要像调用 toLowerCase() 那样进行复制。
     *
     * @param string 要检查的字符串
     * @param prefix 要比较的前缀
     * @return 如果提供的字符串以忽略大小写的方式开始于提供的前缀，则返回 true
     * @throws NullPointerException     如果前缀为 null
     * @throws IllegalArgumentException 如果字符串为 null
     */
    public static boolean startsWithIgnoreCase(final String string, final String prefix) throws IllegalArgumentException, NullPointerException {
        // 检查字符串的长度是否小于前缀的长度，如果是，则直接返回 false
        if (string.length() < prefix.length()) {
            return false;
        }
        // 使用区域匹配方法检查字符串是否以指定前缀开头，忽略大小写
        return string.regionMatches(true, 0, prefix, 0, prefix.length());
    }

}