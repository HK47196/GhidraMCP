plugins {
    java
    id("distribution")
}

group = "com.lauriewired"
version = "1.0-SNAPSHOT"

java {
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

repositories {
    mavenCentral()
}

dependencies {
    // Ghidra JARs as file dependencies
    implementation(files("lib/Generic.jar"))
    implementation(files("lib/SoftwareModeling.jar"))
    implementation(files("lib/Project.jar"))
    implementation(files("lib/Docking.jar"))
    implementation(files("lib/Decompiler.jar"))
    implementation(files("lib/Utility.jar"))
    implementation(files("lib/Base.jar"))
    implementation(files("lib/Gui.jar"))

    // BSim dependencies
    implementation(files("lib/BSim.jar"))
    implementation(files("lib/commons-dbcp2-2.9.0.jar"))
    implementation(files("lib/commons-logging-1.2.jar"))
    implementation(files("lib/commons-pool2-2.11.1.jar"))
    implementation(files("lib/h2-2.2.220.jar"))
    implementation(files("lib/postgresql-42.7.6.jar"))

    // JUnit 5 (test only)
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.0")
    testImplementation("org.mockito:mockito-core:5.5.0")
    testImplementation("org.mockito:mockito-junit-jupiter:5.5.0")
}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    // Use custom MANIFEST.MF
    manifest {
        from("src/main/resources/META-INF/MANIFEST.MF")
    }

    // Set a fixed name for the JAR without version
    archiveFileName.set("GhidraMCP.jar")

    // Exclude the App class
    exclude("**/App.class")
}

// Task to copy runtime dependencies to build/lib
val copyDependencies by tasks.registering(Copy::class) {
    from(configurations.runtimeClasspath)
    into("${layout.buildDirectory.get()}/lib")
}

// Create the Ghidra extension ZIP
distributions {
    main {
        distributionBaseName.set("GhidraMCP")
        contents {
            // Copy extension.properties and Module.manifest
            from("src/main/resources") {
                include("extension.properties")
                include("Module.manifest")
                into("GhidraMCP")
            }

            // Copy the built JAR
            from(tasks.jar) {
                into("GhidraMCP/lib")
            }
        }
    }
}

// Make sure the JAR is built before creating the distribution
tasks.named("distZip") {
    dependsOn(tasks.jar)
}

tasks.named("distTar") {
    dependsOn(tasks.jar)
}

// Make copyDependencies run during the prepare-package phase equivalent
tasks.named("assemble") {
    dependsOn(copyDependencies)
}
