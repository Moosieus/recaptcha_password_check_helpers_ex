# Builds the parity vector generator: a standalone jar wrapping Google's
# recaptcha-password-check-helpers. Only needed to regenerate test fixtures.
FROM maven:3.9.9-eclipse-temurin-21 AS build

WORKDIR /build

# Resolve dependencies first so source edits do not re-download the world.
COPY pom.xml ./
RUN mvn -B -q -Dmaven.repo.local=/root/.m2/repository dependency:go-offline

COPY src ./src
RUN mvn -B -q -Dmaven.repo.local=/root/.m2/repository package

FROM eclipse-temurin:21-jre

WORKDIR /app
COPY --from=build /build/target/pld-parity.jar /app/pld-parity.jar

ENV LANG=C.UTF-8
ENTRYPOINT ["java", "-Dfile.encoding=UTF-8", "-jar", "/app/pld-parity.jar"]
