import org.eclipse.jgit.transport.sshd.SshdSessionFactoryBuilder;
import org.apache.sshd.common.keyprovider.KeyIdentityProvider;

public class TestSshd {
    public void test() {
        SshdSessionFactoryBuilder builder = new SshdSessionFactoryBuilder();
        builder.setDefaultKeysProvider(null);
    }
}
