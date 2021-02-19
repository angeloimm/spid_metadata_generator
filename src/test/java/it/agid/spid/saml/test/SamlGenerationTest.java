package it.agid.spid.saml.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.agid.spid.saml.core.SpMetadataBuilder;
import it.agid.spid.saml.core.dto.SamlAssertionConsumerServiceUtil;
import it.agid.spid.saml.core.dto.SamlBindingUtils;
import it.agid.spid.saml.core.dto.SamlFpaCessionarioCommittente;
import it.agid.spid.saml.core.dto.SamlFpaDatiAnagraficiConcessionario;
import it.agid.spid.saml.core.dto.SamlFpaFiscaleIva;
import it.agid.spid.saml.core.dto.SamlFpaSede;
import it.agid.spid.saml.core.dto.SamlOrganizationDto;
import it.agid.spid.saml.core.dto.SamlOtherContactPerson;
import it.agid.spid.saml.core.utils.AgidUtils;
import it.agid.spid.saml.core.utils.OpenSAMLUtils;
import it.agid.spid.saml.core.utils.SamlBindingTypes;

public class SamlGenerationTest {
	private static final Logger logger = LoggerFactory.getLogger(SamlGenerationTest.class.getName());
	//Necessario in questo caso. Non partendo con spring security bisogna inzializzare opensaml
	@BeforeEach
	public void initiOpenSaml() {
		try {
			OpenSAMLUtils.openSamlBootstrap();
			//Init.init();
		} catch (Exception e) {
			logger.error("Errore nella inizializzazione di open saml", e);
			throw new RuntimeException(e);
		}
	}
	@Test
	public void creaSpMetadata() {
		try {
			SpMetadataBuilder spBuilder = SpMetadataBuilder.getInstance();
			String entityId = "https://sample-entity-id/";
			boolean wantAuthnRequestSigned = true;
			boolean wantAssertionsSigned = true;
			String supportedProtocol = "urn:oasis:names:tc:SAML:2.0:protocol";
			//Carico il p12 (può avere estensione p12 o pfx) e utilizzo questo per i cerficati
			String pwd = "esempio.certificato";
			String alias = null;

			InputStream is = new FileInputStream(new File("certificate/esempio.pfx"));
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(is, pwd.toCharArray());
			List<String> result = new ArrayList<String>();
			Enumeration<String> aliases = ks.aliases();
			//Considero la presenza di un solo alias nel pfx
			while (aliases.hasMoreElements()) {
				alias = (String) aliases.nextElement();
				Certificate[] certs = ks.getCertificateChain(alias);
				if( certs != null && certs.length > 0 ) {
					for (int i = 0; i < certs.length; i++) {
						X509Certificate certificato = (X509Certificate)certs[i];
						String base64 = new String(Base64.encodeBase64(certificato.getEncoded()));
						result.add(base64);
					}
				}
			}
			SamlBindingUtils bu = new SamlBindingUtils();
			bu.setBindingType(SamlBindingTypes.POST);
			bu.setLocation("https://single-loglout-url-post");
			bu.setResponseLocation("https://single-loglout-url-post/response-location");
			List<SamlBindingUtils> singleLogoutService = Collections.singletonList(bu);
			List<String> nameIds = Collections.singletonList(NameIDType.TRANSIENT);
			SamlAssertionConsumerServiceUtil defaultAssertionConsumer = new SamlAssertionConsumerServiceUtil();
			defaultAssertionConsumer.setDefaultElement(true);
			defaultAssertionConsumer.setIndex(0);
			SamlBindingUtils assertionConumerBinding = new SamlBindingUtils();
			assertionConumerBinding.setBindingType(SamlBindingTypes.POST);
			assertionConumerBinding.setLocation("https://assertion-consumer-binding-post");
			assertionConumerBinding.setResponseLocation("https://assertion-consumer-binding-post/response-location");
			defaultAssertionConsumer.setSamlBinding(assertionConumerBinding);
			List<SamlAssertionConsumerServiceUtil> assertionConsumerServices = Collections.singletonList(defaultAssertionConsumer);
			SamlOrganizationDto organization = new SamlOrganizationDto();
			organization.setOrganizationDisplayName("Organization Display Name");
			organization.setOrganizationName("Organization Name");
			organization.setOrganizationUrl("https://organization-url/");
			SamlOtherContactPerson otherContactPerson = new SamlOtherContactPerson();
			otherContactPerson.setSpPubblico(true);
			otherContactPerson.setEmailAddress("email@email.it");
			otherContactPerson.setFiscalCode("fiscal code");
			otherContactPerson.setIpaCode("ipa code");
			otherContactPerson.setTelephoneNumber("telefono");
			EntityDescriptor spEntityDescr = spBuilder.buildSpMetadata(	entityId,
					wantAuthnRequestSigned,
					wantAssertionsSigned,
					supportedProtocol,
					result,
					result,
					singleLogoutService,
					nameIds,
					assertionConsumerServices,
					organization,
					otherContactPerson,
					null,
					AgidUtils.agidSpidEidasAttributes());
			String xmlSp = OpenSAMLUtils.samlObjectToString(spEntityDescr);
			PrivateKey privateKey = (PrivateKey) ks.getKey(alias, pwd.toCharArray());
			X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
			OpenSAMLUtils.signSamlObj(spEntityDescr, privateKey, cert);
			String xmlSpFirmato = OpenSAMLUtils.samlObjectToString(spEntityDescr);
			logger.info("File originale {}. File firmato {}",xmlSp, xmlSpFirmato);
		} catch (Exception e) {
			logger.error("Errore nella creazione del metadata", e);
		}
	}
	@Test
	public void creaSpMetadataEntePrivato() {
		try {
			SpMetadataBuilder spBuilder = SpMetadataBuilder.getInstance();
			String entityId = "https://test-ente-privato-entity-id/";
			boolean wantAuthnRequestSigned = true;
			boolean wantAssertionsSigned = true;
			String alias = null;
			String supportedProtocol = "urn:oasis:names:tc:SAML:2.0:protocol";
			//Carico il p12 (può avere estensione p12 o pfx) e utilizzo questo per i cerficati
			String pwd = "esempio.certificato";
			InputStream is = new FileInputStream(new File("certificate/esempio.pfx"));
			KeyStore ks = KeyStore.getInstance("PKCS12");
			ks.load(is, pwd.toCharArray());
			List<String> result = new ArrayList<String>();
			Enumeration<String> aliases = ks.aliases();
			while (aliases.hasMoreElements()) {
				alias = (String) aliases.nextElement();
				Certificate[] certs = ks.getCertificateChain(alias);
				if( certs != null && certs.length > 0 ) {
					for (int i = 0; i < certs.length; i++) {
						X509Certificate certificato = (X509Certificate)certs[i];
						String base64 = new String(Base64.encodeBase64(certificato.getEncoded()));
						result.add(base64);
					}
				}
			}
			SamlBindingUtils bu = new SamlBindingUtils();
			bu.setBindingType(SamlBindingTypes.POST);
			bu.setLocation("https://test-ente-privato-single-logout-post");
			bu.setResponseLocation("https://test-ente-privato-single-logout-post/response-location");
			List<SamlBindingUtils> singleLogoutService = Collections.singletonList(bu);
			List<String> nameIds = Collections.singletonList(NameIDType.TRANSIENT);
			SamlAssertionConsumerServiceUtil defaultAssertionConsumer = new SamlAssertionConsumerServiceUtil();
			defaultAssertionConsumer.setDefaultElement(true);
			defaultAssertionConsumer.setIndex(0);
			SamlBindingUtils assertionConumerBinding = new SamlBindingUtils();
			assertionConumerBinding.setBindingType(SamlBindingTypes.POST);
			assertionConumerBinding.setLocation("https://test-ente-privato-assertion-consumer-post");
			assertionConumerBinding.setResponseLocation("https://test-ente-privato-assertion-consumer-post/response-location");
			defaultAssertionConsumer.setSamlBinding(assertionConumerBinding);
			List<SamlAssertionConsumerServiceUtil> assertionConsumerServices = Collections.singletonList(defaultAssertionConsumer);
			SamlOrganizationDto organization = new SamlOrganizationDto();
			organization.setOrganizationDisplayName("Organization Display Name");
			organization.setOrganizationName("Organization Name");
			organization.setOrganizationUrl("https://organization-url/");
			SamlOtherContactPerson otherContactPerson = new SamlOtherContactPerson();
			otherContactPerson.setSpPubblico(false);
			otherContactPerson.setEmailAddress("mail");
			otherContactPerson.setFiscalCode("fiscal code");
			otherContactPerson.setVatNumber("vat_number");
			otherContactPerson.setTelephoneNumber("telefono");
			SamlFpaCessionarioCommittente cessionarioCommittente = new SamlFpaCessionarioCommittente();
			cessionarioCommittente.setCompany("Distinto da company precedente");
			SamlFpaDatiAnagraficiConcessionario datiAnagrafici = new SamlFpaDatiAnagraficiConcessionario();
			datiAnagrafici.setDenominazione("Denominazione datiAnagrafici");
			SamlFpaFiscaleIva fiscaleIva = new SamlFpaFiscaleIva();
			fiscaleIva.setIdCodice("id codice");
			fiscaleIva.setIdPaese("id paese");
			datiAnagrafici.setFiscaleIva(fiscaleIva);
			cessionarioCommittente.setDatiAnagrafici(datiAnagrafici);
			cessionarioCommittente.setMail("email_aziendale@test.it");
			cessionarioCommittente.setTelephoneNumber("telefono azienda");
			SamlFpaSede sede = new SamlFpaSede();
			sede.setCap("cap");
			sede.setComune("comune");
			sede.setIndrizzo("indirizzo");
			sede.setNazione("nazione");
			sede.setNumeroCivico("civico");
			sede.setProvincia("provincia");
			cessionarioCommittente.setSede(sede);
			EntityDescriptor spEntityDescr = spBuilder.buildSpMetadata(	entityId,
					wantAuthnRequestSigned,
					wantAssertionsSigned,
					supportedProtocol,
					result,
					result,
					singleLogoutService,
					nameIds,
					assertionConsumerServices,
					organization,
					otherContactPerson,
					cessionarioCommittente,
					AgidUtils.agidSpidEidasAttributes());
			String xmlSp = OpenSAMLUtils.samlObjectToString(spEntityDescr);
			X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
			PrivateKey privateKey = (PrivateKey) ks.getKey(alias, pwd.toCharArray());
			OpenSAMLUtils.signSamlObj(spEntityDescr, privateKey, cert);
			String xmlSpFirmato = OpenSAMLUtils.samlObjectToString(spEntityDescr);
			logger.info("File originale {}. File firmato {}",xmlSp, xmlSpFirmato);
		} catch (Exception e) {
			logger.error("Errore nella creazione del metadata", e);
		}
	}
}
