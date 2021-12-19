package de.soderer.utilities.worker;

import java.util.Date;

public interface WorkerParentSimple {
	void showUnlimitedProgress();

	void showProgress(Date start, long itemsToDo, long itemsDone);

	void showDone(Date start, Date end, long itemsDone);

	void changeTitle(String text);

	void cancel();
}
