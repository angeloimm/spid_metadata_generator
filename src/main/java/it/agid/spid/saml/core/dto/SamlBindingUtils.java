package it.agid.spid.saml.core.dto;

import java.io.Serializable;

import it.agid.spid.saml.core.utils.SamlBindingTypes;

public class SamlBindingUtils implements Serializable{

	private static final long serialVersionUID = -6493708320315222842L;
	private SamlBindingTypes bindingType;
	private String location;
	private String responseLocation;
	public SamlBindingTypes getBindingType() {
		return bindingType;
	}
	public void setBindingType(SamlBindingTypes bindingType) {
		this.bindingType = bindingType;
	}
	public String getLocation() {
		return location;
	}
	public void setLocation(String location) {
		this.location = location;
	}
	public String getResponseLocation() {
		return responseLocation;
	}
	public void setResponseLocation(String responseLocation) {
		this.responseLocation = responseLocation;
	}
	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((bindingType == null) ? 0 : bindingType.hashCode());
		result = prime * result + ((location == null) ? 0 : location.hashCode());
		result = prime * result + ((responseLocation == null) ? 0 : responseLocation.hashCode());
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
		SamlBindingUtils other = (SamlBindingUtils) obj;
		if (bindingType != other.bindingType)
			return false;
		if (location == null) {
			if (other.location != null)
				return false;
		} else if (!location.equals(other.location))
			return false;
		if (responseLocation == null) {
			if (other.responseLocation != null)
				return false;
		} else if (!responseLocation.equals(other.responseLocation))
			return false;
		return true;
	}
	@Override
	public String toString() {
		return "SamlBindingUtils [bindingType=" + bindingType + ", location=" + location + ", responseLocation="
				+ responseLocation + "]";
	}
}
