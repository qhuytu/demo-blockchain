package blockchain;

import blockchain.utils.StringUtil;

import java.security.PublicKey;

public class TransactionOutput {

    public String id;
    public PublicKey reciepient;
    public float value;
    public String parentTransactionId;

    //Constructor
    public TransactionOutput(PublicKey reciepient, float value, String parentTransactionId) {
        this.reciepient = reciepient;
        this.value = value;
        this.parentTransactionId = parentTransactionId;
        this.id = StringUtil.applySha256(StringUtil.getStringFromKey(reciepient) + value + parentTransactionId);
    }

    public boolean isMine(PublicKey publicKey) {
        return (publicKey == reciepient);
    }

}
