# VaxApp

## About

VaxApp is a web application consisting in an online reservation system for citizens aged 18 years and over who would like to receive their first COVID vaccination (1st or 2nd dose). The system keeps track of the doses received by each individual registered in the system. It also shows statistics about the profile of the individuals who received the vaccination, and provides a forum to ask questions about the vaccination campaign.

## Prerequisites

To run this project,you must have:

- Maven
- Java version 11
- MySQL server with

1.  MySQL user with enough privileges to create the database and handle table creation and updates. The `application.properties` file assumes the following credentials

    - username: `admin`
    - password: `admin`

    If you wish to change this, you are free to modify the `application.properties` file with your own user credentials.

1.  A database named `vaxapp`

## Running the project

### Installation

Clone the repository into a directory of your choice using

> `git clone`

### Database setup

The following steps will take you through the database setup process. Make sure your server is running and take note of the port. The `application.properties` assumes your MySQL server runs on default port **3306**. If this is not the case, please modify the `application.properties` file with the corresponding port number.

In your CLI, Log into database server using and input the password in the prompt

> `mysql -u admin -p`

Create database using

> `create database vaxapp;`

Ensure the database was successfully created using

> `show databases;`

### Run spring application

Clone the repository into a directory of your choice using

> `git clone`

The project can be open in any IDE (we recommend VSCode or Intellij). To run it, use the following command:

> `mvn clean install spring-boot:run`

IntelliJ also provides in-built features for using Maven and running Springboot applications. Simply run Maven lifecycles `clean` and `install`, and then run the `VaxApplication.java` file, which is the entrypoint to the project.

When the application is up and running, the port used will be specified in the terminal. Generally this should be localhost:8080, but it may differ depending on the machine. Please check the terminal to make sure.

If port 8080 is already in use, you will need to modify the `application.properties` file and specify a new port as follows:

> `# server.port = xxxx`

## Authors

- Dragoș Feleaga
- Andrei Costin
- Andra Antal-Berbecaru

## Contribution

- Dragoș Feleaga
  - Frontend Design
  - Partial database setup
  - Appointment system
  - Sessions
  - Vaccination system
  - Partial login/register
  - Dashboard
  - Partial error handling
- Andrei Costin
  - Partial login/register
  - Statistics
  - Profile activity
- Andra Antal-Berbecaru
  - Initial Spring project setup
  - Partial database setup
  - Forum functionality
  - Partial error handling
  - README
