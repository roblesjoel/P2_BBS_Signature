package ch.bfh.evg.jni;

import com.herumi.mcl.Mcl;

public class JNI {

    static {
        initialize();
    }

    private static void initialize() {
        String libName = "libmcljava" + JNI.getOS().fileExtension;
        String fileName = JNI.class.getResource(libName).getFile().replace("%20", " ");
        System.load(fileName);
        Mcl.SystemInit(Mcl.BLS12_381);
    }

    private enum OS {
        MAC_INTEL("mac", "x86_64", ".dylib"),
        MAC_AMD("mac", "aarch64", ".dylib"),
        LINUX("linux", "amd64", ".so"),
        WINDOWS("windows", "amd64", ".dll");

        private final String osName;
        private final String archName;
        private final String fileExtension;

        OS(String osName, String archName, String fileExtension) {
            this.osName = osName;
            this.archName = archName;
            this.fileExtension = fileExtension;
        }
    }

    static OS getOS() {
        String osName = System.getProperty("os.name").toLowerCase();
        String osArch = System.getProperty("os.arch").toLowerCase();
        for (OS os : OS.values()) {
            if (osName.contains(os.osName) && osArch.contains(os.archName)) {
                return os;
            }
        }
        throw new RuntimeException("OS not supported.");
    }

}

