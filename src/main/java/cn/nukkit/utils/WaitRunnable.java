package cn.nukkit.utils;

import java.util.concurrent.ExecutionException;

/**
 * 由 WCPE 在 2024/11/1 14:30 创建
 * <p>
 * Created by WCPE on 2024/11/1 14:30
 * <p>
 * <p>
 * GitHub  : <a href="https://github.com/wcpe">wcpe 's GitHub</a>
 * <p>
 * QQ      : 1837019522
 *
 * @author : WCPE
 */
public abstract class WaitRunnable<T> implements Runnable {
    private enum Status {
        WAITING,
        RUNNING,
        FINISHED,
    }
    Throwable t = null;
    T value = null;
    Status status = Status.WAITING;

    public final void run() {
        synchronized (this) {
            if (status != Status.WAITING) {
                throw new IllegalStateException("Invalid state " + status);
            }
            status = Status.RUNNING;
        }
        try {
            value = evaluate();
        } catch (Throwable t) {
            this.t = t;
        } finally {
            synchronized (this) {
                status = Status.FINISHED;
                this.notifyAll();
            }
        }
    }

    protected abstract T evaluate();

    public synchronized T get() throws InterruptedException, ExecutionException {
        while (status != Status.FINISHED) {
            this.wait();
        }
        if (t != null) {
            throw new ExecutionException(t);
        }
        return value;
    }
}
