package it.agid.spid.saml.core.dto;

import java.io.Serializable;

public class SamlAssertionConsumerServiceUtil implements Serializable {

	private static final long serialVersionUID = 2963803502792566017L;
	private SamlBindingUtils samlBinding;
	private int index;
	private boolean defaultElement;
	public SamlBindingUtils getSamlBinding() {
		return samlBinding;
	}
	public void setSamlBinding(SamlBindingUtils samlBinding) {
		this.samlBinding = samlBinding;
	}
	public int getIndex() {
		return index;
	}
	public void setIndex(int index) {
		this.index = index;
	}
	public boolean isDefaultElement() {
		return defaultElement;
	}
	public void setDefaultElement(boolean defaultElement) {
		this.defaultElement = defaultElement;
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (defaultElement ? 1231 : 1237);
		result = prime * result + index;
		result = prime * result + ((samlBinding == null) ? 0 : samlBinding.hashCode());
		return result;
	}
	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		SamlAssertionConsumerServiceUtil other = (SamlAssertionConsumerServiceUtil) obj;
		if (defaultElement != other.defaultElement)
			return false;
		if (index != other.index)
			return false;
		if (samlBinding == null) {
			if (other.samlBinding != null)
				return false;
		} else if (!samlBinding.equals(other.samlBinding))
			return false;
		return true;
	}
	@Override
	public String toString() {
		return "SamlAssertionConsumerServiceUtil [samlBinding=" + samlBinding + ", index=" + index + ", defaultElement="
				+ defaultElement + "]";
	}
}
