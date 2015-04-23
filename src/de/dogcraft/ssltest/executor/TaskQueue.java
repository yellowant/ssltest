package de.dogcraft.ssltest.executor;

import java.lang.Thread.State;
import java.util.LinkedList;
import java.util.List;
import java.util.PriorityQueue;

public class TaskQueue {

    public static void main(String[] args) {
        final TaskQueue q = new TaskQueue();

        Task t1 = q.new Task() {

            @Override
            public void run() {
                System.out.println("Hallo Welt!");

                Task t2 = getQueue().new Task() {

                    @Override
                    public void run() {
                        System.out.println("Task that we just created ...");
                    }

                };

                Task t3 = getQueue().new Task() {

                    @Override
                    public void run() {
                        System.out.println("This is Task 3");
                    }

                };

                Task t4 = getQueue().new Task() {

                    @Override
                    public void run() {
                        System.out.println("And finally Task 4");
                    }

                };

                t4.dependsOn.add(t3);
                t4.dependsOn.add(t2);

                t2.dependsOn.add(t3);

                getQueue().addTask(t2);
                getQueue().addTask(t3);
                getQueue().addTask(t4);
            }

        };

        q.addTask(t1);

        q.start();

        while ( !q.isCompleted()) {
            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                e.printStackTrace();
            }
        }
    }

    protected synchronized void addTask(Task task) {
        tasks.add(task);
        if (isRunning()) {
            this.start();
        }
    }

    private final PriorityQueue<Task> tasks = new PriorityQueue<Task>();

    private Thread taskThread = null;

    private boolean running = false;

    public boolean isRunning() {
        return this.running;
    }

    public boolean isCompleted() {
        return isRunning() && tasks.isEmpty() && (null == taskThread || State.TERMINATED == taskThread.getState());
    }

    private synchronized void start() {
        running = true;

        if (null != taskThread) {
            if ( !taskThread.isAlive()) {
                taskThread = null;
            }
        }

        if (null == taskThread) {
            taskThread = new Thread() {

                @Override
                public void run() {
                    super.run();

                    synchronized (TaskQueue.this) {
                        while ( !TaskQueue.this.tasks.isEmpty()) {
                            Task t = TaskQueue.this.tasks.poll();

                            if (null == t) {
                                break;
                            }

                            try {
                                if ( !t.isBlocked()) {
                                    t.run();
                                } else {
                                    System.out.println("Found a task that has highest priority yet still is blocked!");
                                }
                            } finally {
                                t.markCompleted();
                            }
                        }
                    }
                }
            };
        }

        if (State.NEW == taskThread.getState()) {
            taskThread.start();
        }
    }

    public abstract class Task implements Runnable, Comparable<Task> {

        private boolean completed = false;

        private List<Task> dependsOn = new LinkedList<Task>();

        public boolean isBlocked() {
            if (dependsOn.isEmpty()) {
                return false;
            }

            for (Task dependentTask : dependsOn) {
                dependentTask.isCompleted();
            }

            return false;
        }

        public boolean isCompleted() {
            return completed;
        }

        public void markCompleted() {
            completed = true;
        }

        public boolean isDependentOn(Task task) {
            return dependsOn.contains(task);
        }

        @Override
        public int compareTo(Task other) {
            if (this.isBlocked() && !other.isBlocked()) {
                return -1;
            } else if ( !this.isBlocked() && other.isBlocked()) {
                return 1;
            }

            if (this.isDependentOn(other)) {
                return -1;
            } else if (other.isDependentOn(this)) {
                return 1;
            }

            return this.dependsOn.size() - other.dependsOn.size();
        }

        public TaskQueue getQueue() {
            return TaskQueue.this;
        }

    }

}
