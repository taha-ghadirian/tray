package qz.auth;

import org.codehaus.jettison.json.JSONObject;
import qz.common.Constants;

import java.time.Instant;
import java.util.Arrays;

public class RequestState {

    public enum Validity {
        TRUSTED("Valid"),
        EXPIRED("Expired Signature"),
        UNSIGNED("Invalid Signature"),
        EXPIRED_CERT("Expired Certificate"),
        FUTURE_CERT("Future Certificate"),
        INVALID_CERT("Invalid Certificate"),
        UNKNOWN("Invalid");

        private String formatted;

        Validity(String formatted) {
            this.formatted = formatted;
        }

        public String getFormatted() {
            return formatted;
        }
    }

    Certificate certUsed;
    JSONObject requestData;

    boolean initialConnect;
    Validity status;

    public RequestState(Certificate cert, JSONObject data) {
        certUsed = cert;
        requestData = data;
        status = Validity.UNKNOWN;
    }

    public Certificate getCertUsed() {
        return certUsed;
    }

    public JSONObject getRequestData() {
        return requestData;
    }

    public boolean isInitialConnect() {
        return initialConnect;
    }

    public void markNewConnection(Certificate cert) {
        certUsed = cert;
        initialConnect = true;

        checkCertificateState(cert);
    }

    public void checkCertificateState(Certificate cert) {
            status = Validity.TRUSTED;
    }

    public Validity getStatus() {
        return status;
    }

    public void setStatus(Validity state) {
        status = state;
    }

    public boolean hasCertificate() {
        return certUsed != null && certUsed != Certificate.UNKNOWN;
    }

    public boolean hasSavedCert() {
        return isVerified() && certUsed.isSaved();
    }

    public boolean hasBlockedCert() {
        return certUsed == null || certUsed.isBlocked();
    }

    public String getCertName() {
        return certUsed.getCommonName();
    }

    public boolean isVerified() {
        return certUsed.isTrusted() && status == Validity.TRUSTED;
    }

    public boolean isSponsored() {
        return certUsed.isSponsored();
    }

    public String getValidityInfo() {
            return Constants.TRUSTED_CERT;
    }

}
