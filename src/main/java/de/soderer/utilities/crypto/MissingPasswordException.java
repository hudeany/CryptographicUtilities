package de.soderer.utilities.crypto;

public class MissingPasswordException extends Exception {
	private static final long serialVersionUID = -5869461272078364993L;

	public MissingPasswordException() {
		super();
	}

	public MissingPasswordException(final String message) {
		super(message);
	}
}
