package it.agid.spid.saml.core.dto;
import java.io.Serializable;

public class SamlAttributeDto implements Serializable {

	private static final long serialVersionUID = 6686717184084572889L;
	private String friendlyName;
	private String name;
	
	public SamlAttributeDto() {
		super();
	}
	public SamlAttributeDto(String friendlyName, String name) {
		super();
		this.friendlyName = friendlyName;
		this.name = name;
	}
	public String getFriendlyName() {
		return friendlyName;
	}
	public void setFriendlyName(String friendlyName) {
		this.friendlyName = friendlyName;
	}
	public String getName() {
		return name;
	}
	public void setName(String name) {
		this.name = name;
	}
	
}
