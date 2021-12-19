package de.soderer.utilities.collection;

import java.util.Map;

/**
 * Generic String keyed Map that ignores the String case
 */
public class CaseInsensitiveMap<V> extends AbstractHashMap<String, V> {
	private static final long serialVersionUID = -528027610172636779L;

	public static <V> CaseInsensitiveMap<V> create() {
		return new CaseInsensitiveMap<>();
	}

	public CaseInsensitiveMap() {
		super();
	}

	public CaseInsensitiveMap(final int initialCapacity, final float loadFactor) {
		super(initialCapacity, loadFactor);
	}

	public CaseInsensitiveMap(final int initialCapacity) {
		super(initialCapacity);
	}

	public CaseInsensitiveMap(final Map<? extends String, ? extends V> map) {
		super(map.size());
		putAll(map);
	}

	@Override
	protected String convertKey(final Object key) {
		return key == null ? null : key.toString().toLowerCase();
	}
}
