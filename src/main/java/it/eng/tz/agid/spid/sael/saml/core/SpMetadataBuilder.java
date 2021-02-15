package it.eng.tz.agid.spid.sael.saml.core;

import java.util.ArrayList;
import java.util.List;

import org.opensaml.core.xml.Namespace;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.impl.XSAnyBuilder;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml.saml2.metadata.AttributeConsumingService;
import org.opensaml.saml.saml2.metadata.Company;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.ContactPersonTypeEnumeration;
import org.opensaml.saml.saml2.metadata.EmailAddress;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.Extensions;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.OrganizationDisplayName;
import org.opensaml.saml.saml2.metadata.OrganizationName;
import org.opensaml.saml.saml2.metadata.OrganizationURL;
import org.opensaml.saml.saml2.metadata.RequestedAttribute;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.opensaml.saml.saml2.metadata.ServiceName;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.TelephoneNumber;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.eng.tz.agid.spid.sael.saml.core.dto.SamlAssertionConsumerServiceUtil;
import it.eng.tz.agid.spid.sael.saml.core.dto.SamlAttributeDto;
import it.eng.tz.agid.spid.sael.saml.core.dto.SamlAttributesConsumingServiceDto;
import it.eng.tz.agid.spid.sael.saml.core.dto.SamlBindingUtils;
import it.eng.tz.agid.spid.sael.saml.core.dto.SamlFpaCessionarioCommittente;
import it.eng.tz.agid.spid.sael.saml.core.dto.SamlOrganizationDto;
import it.eng.tz.agid.spid.sael.saml.core.dto.SamlOtherContactPerson;
import it.eng.tz.agid.spid.sael.saml.core.utils.OpenSAMLUtils;
import it.eng.tz.agid.spid.sael.saml.core.utils.StringUtil;
/**
 * Singleton per la costruzione del metadata di un ServiceProvider
 *
 */
public class SpMetadataBuilder extends AbstractMetadataBuilder {
	private static final Logger logger = LoggerFactory.getLogger(SpMetadataBuilder.class.getName());
	public static final String FPA_NS_URI = "http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2";
	public static final String FPA_NS_PREFIX = "fpa";
	public static final String SPID_NS_URI = "https://spid.gov.it/saml-extensions";
	public static final String SPID_NS_PREFIX = "spid";	
	
	private static SpMetadataBuilder _INSTANCE;
	/**
	 * Costruttore privato
	 */
	private SpMetadataBuilder() {
	}
	/**
	 * Recupero l'istanza dell'oggetto
	 * @return -l'istanza 
	 */
	public static synchronized SpMetadataBuilder getInstance() {
		if( _INSTANCE == null ) {
			_INSTANCE = new SpMetadataBuilder();
		}
		return _INSTANCE;
	}
	/**
	 * Costruisce l'oggetto {@link EntityDescriptor} che rappresenta il metadata dell ServiceProvider
	 * @param entityId -l'entity ID. Deve essere un URI (anche se non corrispondente ad un sito internete ma comunque un URI)
	 * @param wantAuthnRequestSigned -indica se la AuthRequest deve essere firmata. Per <strong>SPID</strong> deve essere <strong>true</strong>
	 * @param wantAssertionsSigned -indica se le assetion devono essere firmate. Per <strong>SPID</strong> deve essere <strong>true</strong>
	 * @param supportedProtocol Il protocollo supportato. Per <strong>SPID</strong> deve essere <strong>urn:oasis:names:tc:SAML:2.0:protocol</strong>
	 * @param base64SigningCertificate {@link List} di {@link String}contenente i certificati (in base 64) che verranno utilizzati per la fase di firma (signing)
	 * @param base64EncryptionCertificate {@link List} di {@link String}contenente i certificati (in base 64) che verranno utilizzati per la fase di encryption
	 * @param singleLogoutService {@link List} di oggetti {@link SamlBindingUtils} per costruire i vari {@link SingleLogoutService}
	 * @param nameIds  {@link List} di {@link String}. Per <strong>SPID</strong> deve essere <strong> {@link NameIDType#TRANSIENT} </strong>
	 * @param assertionConsumerServices {@link List} di {@link SamlAssertionConsumerServiceUtil} per costruire gli {@link AssertionConsumerService}
	 * @param organization Riferimenti da usare per la costruzione di {@link Organization}
	 * @param otherContactPerson Riferimenti da utilizzare per costruire gli oggetti {@link ContactPerson}
	 * @param cessionarioCommittente Riferimenti da utilizzare per il caso di fatturazione. Vedere specifiche SPID https://www.agid.gov.it/sites/default/files/repository_files/spid-avviso-n29-specifiche_sp_pubblici_e_privati.pdf
	 * @param acss: {@link List} di {@link SamlAttributesConsumingServiceDto} indicante l'elenco degli attributi saml da richiedere in questo metadata
	 * @return
	 */
	public EntityDescriptor buildSpMetadata(String entityId, 
			boolean wantAuthnRequestSigned, 
			boolean wantAssertionsSigned, 
			String supportedProtocol,
			List<String> base64SigningCertificate,
			List<String> base64EncryptionCertificate,
			List<SamlBindingUtils> singleLogoutService,
			List<String> nameIds, //Per SPID deve esserci solo transient
			List<SamlAssertionConsumerServiceUtil> assertionConsumerServices,
			SamlOrganizationDto organization,
			SamlOtherContactPerson otherContactPerson,
			SamlFpaCessionarioCommittente cessionarioCommittente,
			List<SamlAttributesConsumingServiceDto> acss
			) {

		EntityDescriptor ed = OpenSAMLUtils.buildSAMLObject(EntityDescriptor.class);
		//SPID name space 
		Namespace spidNs = new Namespace(SPID_NS_URI, SPID_NS_PREFIX);
		ed.getNamespaceManager().registerNamespaceDeclaration(spidNs);
		ed.setID(OpenSAMLUtils.generateSecureRandomId());
		ed.setEntityID(entityId);
		SPSSODescriptor spDescriptor = OpenSAMLUtils.buildSAMLObject(SPSSODescriptor.class);
		//Per SPID deve essere true
		spDescriptor.setAuthnRequestsSigned(wantAuthnRequestSigned);
		//Per SPID deve essere true
		spDescriptor.setWantAssertionsSigned(wantAssertionsSigned);
		//Per SPID deve essere "urn:oasis:names:tc:SAML:2.0:protocol"
		spDescriptor.addSupportedProtocol(supportedProtocol);
		//Costruisco Keydescriptor di tipo signing ed encryption
		if( base64SigningCertificate != null && !base64SigningCertificate.isEmpty() ) {

			spDescriptor.getKeyDescriptors().add(buildKeyDescr(base64SigningCertificate, UsageType.SIGNING));
		}else {
			if( logger.isWarnEnabled() ) {
				logger.warn("Nessun certificato in base 64 passato per lo usage di tipo SIGNING");
			}
		}
		if( base64EncryptionCertificate != null && !base64EncryptionCertificate.isEmpty() ) {
			spDescriptor.getKeyDescriptors().add(buildKeyDescr(base64EncryptionCertificate, UsageType.ENCRYPTION));
		}else {
			if( logger.isWarnEnabled() ) {
				logger.warn("Nessun certificato in base 64 passato per lo usage di tipo ENCRYPTION");
			}
		}
		List<SingleLogoutService> slss = buildSingleLogoutServices(singleLogoutService);
		if( slss != null ) {

			spDescriptor.getSingleLogoutServices().addAll(slss);
		}
		nameIds.forEach(nameId->{
			NameIDFormat nidf = OpenSAMLUtils.buildSAMLObject(NameIDFormat.class);
			nidf.setFormat(nameId);
			spDescriptor.getNameIDFormats().add(nidf);
		});
		spDescriptor.getAssertionConsumerServices().addAll(buildAssertionConsumerServices(assertionConsumerServices));
		//Costruzione attributi SPID ed eidas
		spDescriptor.getAttributeConsumingServices().addAll(buildConsumingService(acss));
		Organization organiza = buildOrganization(organization);
		ed.setOrganization(organiza);
		String companyName = null;
		if( organiza.getOrganizationNames() != null && !organiza.getOrganizationNames().isEmpty() && organiza.getOrganizationNames().get(0) != null ) {
			companyName = organiza.getOrganizationNames().get(0).getValue();
		}
		ed.getContactPersons().add(buildOtherContactType(otherContactPerson, companyName));
		if( !otherContactPerson.isSpPubblico() ) {
			if( cessionarioCommittente != null ) {
			
				ed.getContactPersons().add(buildBillingContactType(cessionarioCommittente));
			}else {
				if( logger.isWarnEnabled() ) {
					logger.warn("Siamo in caso di ente privato ma cessionario committente nullo");
				}
			}
		}
		ed.getRoleDescriptors(SPSSODescriptor.DEFAULT_ELEMENT_NAME).add(spDescriptor);
		return ed;
	}

	/**
	 * Costruisce l'oggetto {@link ContactPerson} con tipo {@link ContactPersonTypeEnumeration#BILLING}
	 * @param cessionCommittente; oggetto {@link SamlFpaCessionarioCommittente} contenente i dati per la costruzione del tag CessionarioCommittente
	 * @return il {@link ContactPerson} creato
	 */
	private ContactPerson buildBillingContactType(SamlFpaCessionarioCommittente cessionCommittente) {
		ContactPerson cp = OpenSAMLUtils.buildSAMLObject(ContactPerson.class);
		cp.setType(ContactPersonTypeEnumeration.BILLING);
		Extensions extensions = OpenSAMLUtils.buildSAMLObject(Extensions.class);
		//Agenzia entrate name space 
		Namespace fpaNs = new Namespace(FPA_NS_URI, FPA_NS_PREFIX);
		extensions.getNamespaceManager().registerNamespaceDeclaration(fpaNs);
		extensions.getUnknownXMLObjects().addAll(fpaExtensions(cessionCommittente));
		cp.setExtensions(extensions);
		if( !StringUtil.isEmptyString(cessionCommittente.getCompany()) ) {

			Company company = OpenSAMLUtils.buildSAMLObject(Company.class);
			company.setName(cessionCommittente.getCompany());
			cp.setCompany(company);
		}
		if( StringUtil.isEmptyString(cessionCommittente.getMail()) ) {
			throw new IllegalArgumentException("Nessun indirizzo mail passato ["+cessionCommittente.getMail()+"]");
		}
		EmailAddress email = OpenSAMLUtils.buildSAMLObject(EmailAddress.class);
		email.setAddress(cessionCommittente.getMail());
		cp.getEmailAddresses().add(email);
		if( !StringUtil.isEmptyString(cessionCommittente.getTelephoneNumber()) ) {
			TelephoneNumber telephone = OpenSAMLUtils.buildSAMLObject(TelephoneNumber.class);
			telephone.setNumber(cessionCommittente.getTelephoneNumber());
			cp.getTelephoneNumbers().add(telephone);
		}
		return cp;
	}
	
	/**
	 * Costruisce l'oggetto {@link ContactPerson} con tipo {@link ContactPersonTypeEnumeration#OTHER}
	 * @param otherContactPerson: {@link SamlOtherContactPerson} contiene i dati per la costruzione del tag ContactPerson con tipo OTHER
	 * @param companyName nome organizzazione preso da {@link Organization}
	 * @return il {@link ContactPerson} creato
	 */
	private ContactPerson buildOtherContactType(SamlOtherContactPerson otherContactPerson, String companyName) {
		ContactPerson cp = OpenSAMLUtils.buildSAMLObject(ContactPerson.class);
		cp.setType(ContactPersonTypeEnumeration.OTHER);
		Extensions extensions = OpenSAMLUtils.buildSAMLObject(Extensions.class);
		extensions.getUnknownXMLObjects().addAll(spidExtensions(otherContactPerson));
		cp.setExtensions(extensions);
		if( !StringUtil.isEmptyString(companyName) ) {

			Company company = OpenSAMLUtils.buildSAMLObject(Company.class);
			company.setName(companyName);
			cp.setCompany(company);
		}
		if( StringUtil.isEmptyString(otherContactPerson.getEmailAddress()) ) {
			throw new IllegalArgumentException("Nessun indirizzo mail passato ["+otherContactPerson.getEmailAddress()+"]");
		}
		EmailAddress email = OpenSAMLUtils.buildSAMLObject(EmailAddress.class);
		email.setAddress(otherContactPerson.getEmailAddress());
		cp.getEmailAddresses().add(email);
		if( !StringUtil.isEmptyString(otherContactPerson.getTelephoneNumber()) ) {
			TelephoneNumber telephone = OpenSAMLUtils.buildSAMLObject(TelephoneNumber.class);
			telephone.setNumber(otherContactPerson.getTelephoneNumber());
			cp.getTelephoneNumbers().add(telephone);
		}
		return cp;
	}	
	/**
	 * Crea le estenzioni per FPA
	 * @param cessionCommittente {@link SamlFpaCessionarioCommittente} contenente le informazioni del cessionario committente
	 * @return Le estensioni richieste
	 */
	private List<XMLObject> fpaExtensions(SamlFpaCessionarioCommittente cessionCommittente){
		List<XMLObject> result = new ArrayList<XMLObject>();
		XSAnyBuilder builder = new XSAnyBuilder();
		//Tag presente solo se SP pubblico (caso regione puglia) e contiene il codice IPA ente
		XSAny cessionarioCommittente = builder.buildObject(FPA_NS_URI,"CessionarioCommittente",FPA_NS_PREFIX);
		//Dati anagrafici del cessionario
		XSAny datiAnagrafici = builder.buildObject(FPA_NS_URI,"DatiAnagrafici",FPA_NS_PREFIX);
		XSAny idFiscaleIVA = builder.buildObject(FPA_NS_URI,"IdFiscaleIVA",FPA_NS_PREFIX);
		List<XMLObject> elementiIdFiscaleIva = new ArrayList<XMLObject>();
		XSAny idPaese = builder.buildObject(FPA_NS_URI,"IdPaese",FPA_NS_PREFIX);
		idPaese.setTextContent(cessionCommittente.getDatiAnagrafici().getFiscaleIva().getIdPaese());
		elementiIdFiscaleIva.add(idPaese);
		XSAny idCodice = builder.buildObject(FPA_NS_URI,"IdCodice",FPA_NS_PREFIX);
		idCodice.setTextContent(cessionCommittente.getDatiAnagrafici().getFiscaleIva().getIdCodice());
		elementiIdFiscaleIva.add(idCodice);
		idFiscaleIVA.getUnknownXMLObjects().addAll(elementiIdFiscaleIva);
		datiAnagrafici.getUnknownXMLObjects().add(idFiscaleIVA);
		//Denominazione cessionario
		XSAny anagrafica = builder.buildObject(FPA_NS_URI,"Anagrafica",FPA_NS_PREFIX);
		XSAny denominazione = builder.buildObject(FPA_NS_URI,"Denominazione",FPA_NS_PREFIX);
		denominazione.setTextContent(cessionCommittente.getDatiAnagrafici().getDenominazione());
		anagrafica.getUnknownXMLObjects().add(denominazione);
		datiAnagrafici.getUnknownXMLObjects().add(anagrafica);
		cessionarioCommittente.getUnknownXMLObjects().add(datiAnagrafici);
		
		//Sede
		XSAny sede = builder.buildObject(FPA_NS_URI,"Sede",FPA_NS_PREFIX);
		XSAny indirizzo = builder.buildObject(FPA_NS_URI,"Indirizzo",FPA_NS_PREFIX);
		indirizzo.setTextContent(cessionCommittente.getSede().getIndrizzo());
		sede.getUnknownXMLObjects().add(indirizzo);
		XSAny numeroCivico = builder.buildObject(FPA_NS_URI,"NumeroCivico",FPA_NS_PREFIX);
		numeroCivico.setTextContent(cessionCommittente.getSede().getNumeroCivico());
		sede.getUnknownXMLObjects().add(numeroCivico);
		XSAny cap = builder.buildObject(FPA_NS_URI,"CAP",FPA_NS_PREFIX);
		cap.setTextContent(cessionCommittente.getSede().getCap());
		sede.getUnknownXMLObjects().add(cap);
		XSAny comune = builder.buildObject(FPA_NS_URI,"Comune",FPA_NS_PREFIX);
		comune.setTextContent(cessionCommittente.getSede().getComune());
		sede.getUnknownXMLObjects().add(comune);
		XSAny provincia = builder.buildObject(FPA_NS_URI,"Provincia",FPA_NS_PREFIX);
		provincia.setTextContent(cessionCommittente.getSede().getProvincia());
		sede.getUnknownXMLObjects().add(provincia);
		XSAny nazione = builder.buildObject(FPA_NS_URI,"Nazione",FPA_NS_PREFIX);
		nazione.setTextContent(cessionCommittente.getSede().getNazione());
		sede.getUnknownXMLObjects().add(nazione);
		cessionarioCommittente.getUnknownXMLObjects().add(sede);
		result.add(cessionarioCommittente);
		return result;
	}
	/**
	 * Crea le estensioni SPID
	 * @param otherContactPerson oggetto {@link SamlOtherContactPerson} contenente le informazioni per creare le estensioni
	 * @return le estensioni necessarie per SPID
	 */
	private List<XMLObject> spidExtensions(SamlOtherContactPerson otherContactPerson) {
		List<XMLObject> result = new ArrayList<XMLObject>();
		XSAnyBuilder builder = new XSAnyBuilder();
		if( otherContactPerson.isSpPubblico() ) {
			if( StringUtil.isEmptyString(otherContactPerson.getIpaCode()) ) {
				throw new IllegalArgumentException("Siamo nel caso di SP pubblico. Nessun IPA Code passato ["+otherContactPerson.getIpaCode()+"]");
			}
			//Tag presente solo se SP pubblico (caso regione puglia) e contiene il codice IPA ente
			XSAny ipaCode = builder.buildObject(SPID_NS_URI,"IPACode",SPID_NS_PREFIX);
			ipaCode.setTextContent(otherContactPerson.getIpaCode());
			result.add(ipaCode);
			//Tag vuoto, obbligatorio per il SP pubblico
			XSAny pubblico = builder.buildObject(SPID_NS_URI,"Public",SPID_NS_PREFIX);
			result.add(pubblico);
		}else {
			if( StringUtil.isEmptyString(otherContactPerson.getVatNumber()) ) {
				throw new IllegalArgumentException("Siamo nel caso di SP privato. Nessun Vat number passato ["+otherContactPerson.getVatNumber()+"]");
			}
			//Tag presente solo se SP privato (NON è il caso regione puglia) e contiene il numero di partita IVA dell’organizzazione (comprensivo del codice ISO 3166-1 α-2 del Paese, senza spazi).
			XSAny vatNumber = builder.buildObject(SPID_NS_URI,"VATNumber",SPID_NS_PREFIX);
			vatNumber.setTextContent(otherContactPerson.getVatNumber());
			result.add(vatNumber);	
			//Tag vuoto, obbligatorio per il SP privato.
			XSAny privato = builder.buildObject(SPID_NS_URI,"Private",SPID_NS_PREFIX);
			result.add(privato);
		}
		if( !StringUtil.isEmptyString(otherContactPerson.getFiscalCode()) ) {
			//Tag facoltativo e valorizzato con il CF del SP
			XSAny fiscalCode = builder.buildObject(SPID_NS_URI,"FiscalCode",SPID_NS_PREFIX);
			fiscalCode.setTextContent(otherContactPerson.getFiscalCode());
			result.add(fiscalCode);
		}
		return result;
	}	
	/**
	 * Costruisce l'oggetto {@link Organization}
	 * @param organ la {@link SamlOrganizationDto} che contiene le informazioni dell'organizzazione
	 * @return {@link Organization} creato
	 */
	private Organization buildOrganization(SamlOrganizationDto organ) {
		//Organization
		Organization organization = OpenSAMLUtils.buildSAMLObject(Organization.class);
		OrganizationDisplayName odn = OpenSAMLUtils.buildSAMLObject(OrganizationDisplayName.class);
		odn.setXMLLang("it");
		odn.setValue(organ.getOrganizationDisplayName());
		organization.getDisplayNames().add(odn);
		OrganizationName on = OpenSAMLUtils.buildSAMLObject(OrganizationName.class);
		on.setXMLLang("it");
		on.setValue(organ.getOrganizationName());
		organization.getOrganizationNames().add(on);
		OrganizationURL ou = OpenSAMLUtils.buildSAMLObject(OrganizationURL.class);
		ou.setXMLLang("it");
		ou.setValue(organ.getOrganizationUrl());
		organization.getURLs().add(ou);
		return organization;
	}
	/**
	 * Costruisce l'elenco degli {@link AssertionConsumerService}
	 * @param assertionConsumerServices {@link List} di {@link SamlAssertionConsumerServiceUtil} contenenti le informazioni necessarie
	 * @return {@link List} di {@link AssertionConsumerService} creato
	 */
	private List<AssertionConsumerService> buildAssertionConsumerServices(List<SamlAssertionConsumerServiceUtil> assertionConsumerServices) {
		if( assertionConsumerServices == null || assertionConsumerServices.isEmpty() ) {
			throw new IllegalArgumentException("Passato un elenco di assertion consumer service nullo o vuoto ["+assertionConsumerServices+"]");
		}
		List<AssertionConsumerService> result = new ArrayList<AssertionConsumerService>(assertionConsumerServices.size());
		assertionConsumerServices.forEach(assertionUtil ->{
			AssertionConsumerService acs = OpenSAMLUtils.buildSAMLObject(AssertionConsumerService.class);
			SamlBindingUtils bindingUtil = assertionUtil.getSamlBinding(); 
			if(StringUtil.isEmptyString(bindingUtil.getLocation())) {
				throw new IllegalArgumentException("Passato location nullo o vuoto ["+bindingUtil.getLocation()+"]");
			}
			acs.setBinding(bindingUtil.getBindingType().getBindingType());
			acs.setLocation(assertionUtil.getSamlBinding().getLocation());
			if(!StringUtil.isEmptyString(bindingUtil.getResponseLocation())) {

				acs.setResponseLocation(bindingUtil.getResponseLocation());
			}
			acs.setIndex(assertionUtil.getIndex());
			acs.setIsDefault(assertionUtil.isDefaultElement());
			result.add(acs);
		});
		return result;
	}
	/**
	 * Costruisce il {@link List} di {@link SingleLogoutService} partendo dal {@link List} di {@link SamlBindingUtils}
	 * @param singleLogoutService il {@link List} di {@link SamlBindingUtils} contenente le informazioni necessarie
	 * @return il {@link List} di {@link SingleLogoutService}
	 */
	private List<SingleLogoutService> buildSingleLogoutServices(List<SamlBindingUtils> singleLogoutService) {
		if( singleLogoutService == null || singleLogoutService.isEmpty() ) {
			return null;
		}else {
			List<SingleLogoutService> slss = new ArrayList<SingleLogoutService>(singleLogoutService.size());
			singleLogoutService.forEach(bindingUtil ->{
				SingleLogoutService sls = OpenSAMLUtils.buildSAMLObject(SingleLogoutService.class);
				sls.setBinding(bindingUtil.getBindingType().getBindingType());
				if(StringUtil.isEmptyString(bindingUtil.getLocation())) {
					throw new IllegalArgumentException("Passato location nullo o vuoto ["+bindingUtil.getLocation()+"]");
				}
				sls.setLocation(bindingUtil.getLocation());
				if(!StringUtil.isEmptyString(bindingUtil.getResponseLocation())) {

					sls.setResponseLocation(bindingUtil.getResponseLocation());
				}
				slss.add(sls);
			});
			return slss;
		}
	}
	/**
	 * Costruisce l'oggetto {@link KeyDescriptor} partendo dal {@link List} di certificati in base 64 e dallo {@link UsageType} passato in ingreso
	 * @param base64Cert Il {@link List} di certificati in base 63
	 * @param usage il tipo di {@link UsageType}
	 * @return Il {@link KeyDescriptor} creato
	 */
	private KeyDescriptor buildKeyDescr( List<String> base64Cert, UsageType usage ) {
		KeyDescriptor result = OpenSAMLUtils.buildSAMLObject(KeyDescriptor.class);
		result.setUse(usage);
		KeyInfo keyInfo = OpenSAMLUtils.buildSAMLObject(KeyInfo.class);
		base64Cert.forEach(cer ->{
			X509Data x509Data = OpenSAMLUtils.buildSAMLObject(X509Data.class);
			X509Certificate certificato = OpenSAMLUtils.buildSAMLObject(X509Certificate.class);
			certificato.setValue(cer);
			x509Data.getX509Certificates().add(certificato);
			keyInfo.getX509Datas().add(x509Data);
		});
		result.setKeyInfo(keyInfo);
		return result;
	}
	/**
	 * Costruisce il {@link List} di {@link AttributeConsumingService}
	 * @return il {@link List} creato
	 */
	private List<AttributeConsumingService> buildConsumingService(List<SamlAttributesConsumingServiceDto> acss) {
		List<AttributeConsumingService> result = new ArrayList<AttributeConsumingService>(acss.size());
		acss.forEach(acs -> {
			AttributeConsumingService anAcs = OpenSAMLUtils.buildSAMLObject(AttributeConsumingService.class);
			anAcs.setIndex(acs.getIndex());
			ServiceName serviceName = OpenSAMLUtils.buildSAMLObject(ServiceName.class);
			serviceName.setXMLLang(acs.getServiceNameLang());
			serviceName.setValue(acs.getServiceName());
			anAcs.getNames().add(serviceName);
			List<SamlAttributeDto> attributi = acs.getAttrs();
			attributi.forEach(attributo ->{
				RequestedAttribute samlAttr = OpenSAMLUtils.buildSAMLObject(RequestedAttribute.class);
				if( !StringUtil.isEmptyString(attributo.getFriendlyName()) ) {

					samlAttr.setFriendlyName(attributo.getFriendlyName());
				}
				samlAttr.setName(attributo.getName());
				anAcs.getRequestAttributes().add(samlAttr);
			});
			result.add(anAcs);
		});
		return result;
	}
}
