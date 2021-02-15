/**
 * 
 */
package it.eng.tz.agid.spid.sael.saml.spid.exception;

/**
 * @author angelo
 *
 */
public class SpidCheckerException extends Exception {
	
	private static final long serialVersionUID = 4360100887757501911L;
	private int anomaliaUtente;
	/**
	 * {@inheritDoc}
	 */
	public SpidCheckerException() {
		
	}
	public SpidCheckerException(int anomaliaUtente, String message) {
		super(message);
		this.anomaliaUtente = anomaliaUtente;
	}
	/**
	 * {@inheritDoc}
	 */
	public SpidCheckerException(String message) {
		super(message);
		
	}

	/**
	 * {@inheritDoc}
	 */
	public SpidCheckerException(Throwable cause) {
		super(cause);
		
	}

	/**
	 * {@inheritDoc}
	 */
	public SpidCheckerException(String message, Throwable cause) {
		super(message, cause);
		
	}

	/**
	 * {@inheritDoc}
	 */
	public SpidCheckerException(String message, Throwable cause, boolean enableSuppression,
			boolean writableStackTrace) {
		super(message, cause, enableSuppression, writableStackTrace);
		
	}
	public int getAnomaliaUtente() {
		return anomaliaUtente;
	}
	public void setAnomaliaUtente(int anomaliaUtente) {
		this.anomaliaUtente = anomaliaUtente;
	}
}
