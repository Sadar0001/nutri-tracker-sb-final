# STAGE 1: Build the application
FROM maven:3.8.5-openjdk-17 AS build
WORKDIR /app
COPY . .
# Skip tests to speed up deployment and avoid database connection errors during build
RUN mvn clean package -DskipTests

# STAGE 2: Run the application
FROM openjdk:17-jdk-slim
WORKDIR /app
# Copy the built jar from Stage 1
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
