package it.eng.tz.agid.spid.sael.saml.core;

import java.util.ArrayList;
import java.util.List;

import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.NameIDFormat;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.X509Certificate;
import org.opensaml.xmlsec.signature.X509Data;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import it.eng.tz.agid.spid.sael.saml.core.dto.SamlBindingUtils;
import it.eng.tz.agid.spid.sael.saml.core.utils.OpenSAMLUtils;
import it.eng.tz.agid.spid.sael.saml.core.utils.StringUtil;
/**
 * Singleton per la costruzione del metadata di un ServiceProvider
 *
 */
public class IdpMetadataBuilder extends AbstractMetadataBuilder {
	private static final Logger logger = LoggerFactory.getLogger(IdpMetadataBuilder.class.getName());
	public static final String FPA_NS_URI = "http://ivaservizi.agenziaentrate.gov.it/docs/xsd/fatture/v1.2";
	public static final String FPA_NS_PREFIX = "fpa";
	public static final String SPID_NS_URI = "https://spid.gov.it/saml-extensions";
	public static final String SPID_NS_PREFIX = "spid";	

	private static IdpMetadataBuilder _INSTANCE;
	/**
	 * Costruttore privato
	 */
	private IdpMetadataBuilder() {
	}
	/**
	 * Recupero l'istanza dell'oggetto
	 * @return -l'istanza 
	 */
	public static synchronized IdpMetadataBuilder getInstance() {
		if( _INSTANCE == null ) {
			_INSTANCE = new IdpMetadataBuilder();
		}
		return _INSTANCE;
	}
	/**
	 * Costruisce l'oggetto {@link EntityDescriptor} che rappresenta il metadata dell ServiceProvider
	 * @param entityId -l'entity ID. Deve essere un URI (anche se non corrispondente ad un sito internete ma comunque un URI)
	 * @param wantAuthnRequestSigned -indica se la AuthRequest deve essere firmata. Per <strong>SPID</strong> deve essere <strong>true</strong>
	 * @param wantAssertionsSigned -indica se le assetion devono essere firmate. Per <strong>SPID</strong> deve essere <strong>true</strong>
	 * @param supportedProtocol La stringa di protocollo supportato. Per <strong>SPID</strong> deve essere <strong>urn:oasis:names:tc:SAML:2.0:protocol</strong>
	 * @param base64SigningCertificate {@link List} di {@link String}contenente i certificati (in base 64) che verranno utilizzati per la fase di firma (signing)
	 * @param base64EncryptionCertificate {@link List} di {@link String}contenente i certificati (in base 64) che verranno utilizzati per la fase di encryption
	 * @param singleLogoutService {@link List} di oggetti {@link SamlBindingUtils} per costruire i vari {@link SingleLogoutService}
	 * @param nameIds  {@link List} di {@link String}. Per <strong>SPID</strong> deve essere <strong> {@link NameIDType#TRANSIENT} </strong>
	 * @param singleSignOnService {@link List} di {@link SamlBindingUtils} per costruire l'elenco di URL di tipo {@link SingleSignOnService}
	 * @param organization Riferimenti da usare per la costruzione di {@link Organization}
	 * @return l'oggetto {@link EntityDescriptor} contenente l'oggetto {@link IDPSSODescriptor} creato
	 */
	public EntityDescriptor buildIdpMetadata(	String entityId, 
												DateTime validUntil, 
												Boolean wantAuthnRequestSigned, 
												String supportedProtocol,
												List<String> base64SigningCertificate,
												List<String> base64EncryptionCertificate,
												List<String> nameIds,
												List<SamlBindingUtils> singleSignOnService,
												List<SamlBindingUtils> singleLogoutService) {

		EntityDescriptor ed = OpenSAMLUtils.buildSAMLObject(EntityDescriptor.class);
		ed.setID(OpenSAMLUtils.generateSecureRandomId());
		ed.setEntityID(entityId);
		IDPSSODescriptor idpDescriptor = OpenSAMLUtils.buildSAMLObject(IDPSSODescriptor.class);
		idpDescriptor.setValidUntil(validUntil);
		idpDescriptor.setWantAuthnRequestsSigned(wantAuthnRequestSigned);
		idpDescriptor.addSupportedProtocol(supportedProtocol);
		nameIds.forEach(nameId->{
			NameIDFormat nidf = OpenSAMLUtils.buildSAMLObject(NameIDFormat.class);
			nidf.setFormat(nameId);
			idpDescriptor.getNameIDFormats().add(nidf);
		});
		if( singleLogoutService != null && !singleLogoutService.isEmpty() ) {
		
			idpDescriptor.getSingleLogoutServices().addAll(buildSingleLogoutServices(singleLogoutService));
		}
		idpDescriptor.getSingleSignOnServices().addAll(buildSignleSignOnServices(singleSignOnService));
		//Costruisco Keydescriptor di tipo signing ed encryption
		if( base64SigningCertificate != null && !base64SigningCertificate.isEmpty() ) {

			idpDescriptor.getKeyDescriptors().add(buildKeyDescr(base64SigningCertificate, UsageType.SIGNING));
		}else {
			if( logger.isWarnEnabled() ) {
				logger.warn("Nessun certificato in base 64 passato per lo usage di tipo SIGNING");
			}
		}
		if( base64EncryptionCertificate != null && !base64EncryptionCertificate.isEmpty() ) {
			idpDescriptor.getKeyDescriptors().add(buildKeyDescr(base64EncryptionCertificate, UsageType.ENCRYPTION));
		}else {
			if( logger.isWarnEnabled() ) {
				logger.warn("Nessun certificato in base 64 passato per lo usage di tipo ENCRYPTION");
			}
		}
		ed.getRoleDescriptors(IDPSSODescriptor.DEFAULT_ELEMENT_NAME).add(idpDescriptor);
		return ed;
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
	private List<SingleSignOnService> buildSignleSignOnServices(List<SamlBindingUtils> singleSignOnServices){
		if( singleSignOnServices == null || singleSignOnServices.isEmpty() ) {
			throw new IllegalArgumentException("Nessun URL di single sign on passato. Impossibile proseguire");
		}else {
			List<SingleSignOnService> ssons = new ArrayList<SingleSignOnService>(singleSignOnServices.size());
			singleSignOnServices.forEach(bindingUtil ->{
				SingleSignOnService sls = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
				sls.setBinding(bindingUtil.getBindingType().getBindingType());
				if(StringUtil.isEmptyString(bindingUtil.getLocation())) {
					throw new IllegalArgumentException("Passato location nullo o vuoto ["+bindingUtil.getLocation()+"]");
				}
				sls.setLocation(bindingUtil.getLocation());
				if(!StringUtil.isEmptyString(bindingUtil.getResponseLocation())) {

					sls.setResponseLocation(bindingUtil.getResponseLocation());
				}
				ssons.add(sls);
			});
			return ssons;
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
}