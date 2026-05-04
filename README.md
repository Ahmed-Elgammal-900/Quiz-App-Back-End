<h1 align="center" style="padding: 20px 0">🧠 Quizzer — Backend API ⏱️</h1>

![NestJS](https://img.shields.io/badge/NestJS-E0234E?style=for-the-badge&logo=nestjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?style=for-the-badge&logo=typescript&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-4169E1?style=for-the-badge&logo=postgresql&logoColor=white)
![TypeORM](https://img.shields.io/badge/TypeORM-FE0902?style=for-the-badge&logo=typeorm&logoColor=white)
![JWT](https://img.shields.io/badge/JWT-000000?style=for-the-badge&logo=jsonwebtokens&logoColor=white)
![Passport](https://img.shields.io/badge/Passport-34E27A?style=for-the-badge&logo=passport&logoColor=white)
![Jest](https://img.shields.io/badge/Jest-C21325?style=for-the-badge&logo=jest&logoColor=white)
![GitHub Actions](https://img.shields.io/badge/GitHub_Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white)
![Version](https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)

> A scalable, production-ready REST API for the Quizzer platform, featuring secure JWT-based authentication, comprehensive quiz management, and a dynamic leaderboard system that enables users to evaluate their performance and engage in competitive gameplay

---

## Overview

**Quizzer** is a competitive quiz platform where users can register, take quizzes, and compete on a ranked leaderboard. This is a **backend API** built with NestJS, a progressive Node.js framework, providing a strongly-typed, modular architecture for handling authentication, quiz logic, scoring, and leaderboard ranking.

---

## Features

- 🔐 **JWT Authentication** — Secure user registration, login, and protected routes via JSON Web Tokens stored in cookies
- 📝 **Quiz Management** — Retrieve quizzes and questions with answers, and track user progress across the app
- ✅ **Answer Submission & Scoring** — Submit answers and receive instant calculated scores
- 🏆 **Leaderboard** — Ranked leaderboard tracking top-scoring users across the platform
- 🛡️ **Guards** — NestJS Guards enforce access control on sensitive endpoints
- 🧩 **Modular Architecture** — Clean separation of concerns using NestJS modules
- 🔒 **Security Hardened** — Protection against CSRF, SQL injection, rate limiting, HTTP security headers, and CORS enforcement

---

## Getting Started

### Prerequisites

Make sure you have the following installed:

- [Node.js](https://nodejs.org/) v18+
- [npm](https://www.npmjs.com/) or [yarn](https://yarnpkg.com/)
- A running database instance (PostgreSQL)

### Installation

1. **Clone the repository**

```bash
git clone https://github.com/Ahmed-Elgammal-900/Quiz-App-Back-End.git
cd Quiz-App-Back-End
```

2. **Install dependencies**

```bash
npm install
```

### Environment Variables

Create a `.env` file in the root directory:

```env
DATABASE_URL=database_connection_url
JWT_SECRET=jwt_secret
JWT_REFRESH_SECRET=jwt_refresh_secret
GOOGLE_CALLBACK_URL=google_callback_url (OAuth google auth)
GOOGLE_CLIENT_ID=google_client_id (OAuth google auth)
GOOGLE_CLIENT_SECRET=google_client_secret (OAuth google auth)
FRONT_END_ORIGIN= front_end_url
```

### Running the Server

**Development mode** (with hot reload):

```bash
npm run start:dev
```

**Production build:**

```bash
npm run build
npm run start:prod
```

The server will start at `http://localhost:3000` (or the port defined in your `.env`).

---

## 🧪 Testing

This project includes a comprehensive test suite built with **Jest**

### Running Test

**unit test & integration test**

```bash
npm run test
```

**e2e test**

```bash
npm run test:e2e
```

> 📌 note: `.env` file should exist with configured var for test success

---

## ⚙️ CI/CD

Automated pipeline configured with **GitHub Actions**

---

## Swagger Docs

you will find docs on `http://localhost:3000/docs` (or the port defined in your `.env`)

---

## API Endpoints

### Auth — `/auth`

| Method | Endpoint               | Description                                                  | Auth Required |
| ------ | ---------------------- | ------------------------------------------------------------ | ------------- |
| POST   | `/signup`              | Register a new user                                          | ❌            |
| POST   | `/login`               | Login and receive a token                                    | ❌            |
| GET    | `/google`              | redirect to google auth                                      | ❌            |
| GET    | `/google/callback`     | get google user info to login or signup                      | ❌            |
| GET    | `/exchange`            | exchange oauth code with session tokens                      | ❌            |
| POST   | `/refresh-token`       | rotate access_token and refresh_token                        | ✅            |
| PATCH  | `/change-password`     | change user password                                         | ✅            |
| POST   | `/forget-password`     | request a change for a user password by email                | ❌            |
| POST   | `/reset-password`      | recieve new password with token to change forgotton password | ❌            |
| POST   | `/verify-email`        | verify user email by otp                                     | ❌            |
| POST   | `/resend-otp`          | resend otp for a user on email                               | ❌            |
| POST   | `/verify-access-token` | verify access token                                          | ✅            |
| POST   | `/logout`              | logout user and remove cookie tokens                         | ✅            |

### User — `/user`

| Method | Endpoint | Description                                            | Auth Required |
| ------ | -------- | ------------------------------------------------------ | ------------- |
| GET    | `/`      | retrieve the authenticated user's profile information. | ✅            |
| DELETE | `/`      | delete A user from system and remove cookie tokens     | ✅            |

### Quizzes — `/quizzes`

| Method | Endpoint                          | Description                                                     | Auth Required |
| ------ | --------------------------------- | --------------------------------------------------------------- | ------------- |
| GET    | `/`                               | Get all quizzes with user progress if exist                     | ✅            |
| GET    | `/activities`                     | Retrieves all active quiz activities for the authenticated user | ✅            |
| GET    | `/stats`                          | Get the user stats in the platform                              | ✅            |
| GET    | `/leaderboard`                    | Get leaderboard and ranked users                                | ✅            |
| GET    | `/passed`                         | Get passed quizzes id with badges for the user                  | ✅            |
| GET    | `/questions/:questionId/answers`  | Get the choices of the question                                 | ✅            |
| GET    | `/questions/:questionId/answered` | Get user answer for the question                                | ✅            |
| GET    | `/:quizId/questions`              | Get a questions of the quiz                                     | ✅            |
| GET    | `/:quizId/progress`               | Get progress of specific quiz                                   | ✅            |
| POST   | `/:quizId/start`                  | Begin the quiz                                                  | ✅            |
| POST   | `/:quizId/pause`                  | Pause the started quiz                                          | ✅            |
| POST   | `/:quizId/progress`               | Insert user progress                                            | ✅            |

> 📌 All protected routes require an `cookies token` .

---

## Project Structure

```text
src
├── common
│   ├── decorators
│   │   ├── match.decorator.ts
│   │   ├── public.decorator.ts
│   │   └── user.decorator.ts
│   ├── filters
│   │   └── global-exception.filter.ts
│   ├── guards
│   │   └── jwt-auth.guard.ts
│   └── interceptors
│       ├── logging.interceptor.ts
│       └── transform-response.interceptor.ts
├── config
│   └── db-connectiont.ts
├── modules
│   ├── auth
│   │   ├── constants
│   │   │   ├── auth.constants.ts
│   │   │   └── token-type.constant.ts
│   │   ├── dto
│   │   │   ├── change-password.dto.ts
│   │   │   ├── exchange-query.dto.ts
│   │   │   ├── forget-password.dto.ts
│   │   │   ├── google-auth.dto.ts
│   │   │   ├── login.dto.ts
│   │   │   ├── otp.dto.ts
│   │   │   ├── resend-otp.dto.ts
│   │   │   ├── reset-password.dto.ts
│   │   │   └── signup.dto.ts
│   │   ├── strategies
│   │   │   ├── googleAuth.strategy.ts
│   │   │   ├── jwt.strategy.ts
│   │   │   └── jwtRefresh.strategy.ts
│   │   ├── types
│   │   │   └── response-types.ts
│   │   ├── auth.controller.spec.ts
│   │   ├── auth.controller.ts
│   │   ├── auth.module.ts
│   │   ├── auth.service.spec.ts
│   │   └── auth.service.ts
│   ├── mail
│   │   ├── templates
│   │   │   ├── email-verification.tsx
│   │   │   └── reset-password.tsx
│   │   ├── mail.module.ts
│   │   ├── mail.service.spec.ts
│   │   └── mail.service.ts
│   ├── quiz
│   │   ├── constants
│   │   │   └── quiz-progress-status.ts
│   │   ├── dto
│   │   │   ├── insert-progress.dto.ts
│   │   │   ├── pagination.dto.ts
│   │   │   └── pause-quiz.dto.ts
│   │   ├── entities
│   │   │   ├── answer.entity.ts
│   │   │   ├── question.entity.ts
│   │   │   ├── quiz.entity.ts
│   │   │   ├── user-progress.entity.ts
│   │   │   └── user-quiz-answer.entity.ts
│   │   ├── types
│   │   │   └── quiz.types.ts
│   │   ├── quiz.controller.spec.ts
│   │   ├── quiz.controller.ts
│   │   ├── quiz.module.ts
│   │   ├── quiz.service.spec.ts
│   │   └── quiz.service.ts
│   └── user
│       ├── constants
│       │   └── provider.constant.ts
│       ├── dto
│       │   └── user-response.dto.ts
│       ├── entities
│       │   ├── deletedUser.entity.ts
│       │   ├── token.entity.ts
│       │   └── user.entity.ts
│       ├── user.controller.spec.ts
│       ├── user.controller.ts
│       ├── user.module.ts
│       ├── user.service.spec.ts
│       └── user.service.ts
├── utils
│   └── clear-cookie.ts
├── app.controller.ts
├── app.module.ts
└── main.ts
```

---

## 🏗️ System Architecture

This section outlines the backend architecture of Quizzer, broken down into five diagrams: a high-level overview, module dependency graph, service class diagram, data flow diagram, and database schema.

---

### High-level Overview

A bird's-eye view of how the client interacts with the API and how each module connects to the database.

```mermaid
graph TD
    Client["Client (HTTP)"]

    subgraph NestJS["NestJS Server"]
        Gateway["API Gateway · main.ts"]

        subgraph Modules["Modules"]
            Auth["Auth\nRegister, login, OAuth"]
            User["User\nProfile, account"]
            Quiz["Quiz\nQuestions, answers"]
            Mail["Mail\nOTP"]
        end
    end

    subgraph Database["Database"]
        PG[("PostgreSQL\nUsers, quizzes, answers")]
    end

    subgraph External["External Services"]
        Google["Google OAuth"]
        SMTP["SMTP Server"]
    end

    Client -->|"HTTPS"| Gateway
    Gateway --> Auth
    Gateway --> User
    Gateway --> Quiz

    Auth -.->|"triggers"| Mail
    Auth -->|"OAuth"| Google
    Auth --> PG
    User --> PG
    Quiz --> PG
    Mail -->|"SMTP"| SMTP
```

---

### Module Breakdown

The internal NestJS module dependency graph, showing how modules import and depend on each other.

```mermaid
graph LR
    App["AppModule"]
    Auth["AuthModule"]
    User["UserModule"]
    Quiz["QuizModule"]
    Mail["MailModule"]
    Passport["PassportModule"]
    JWT["JwtModule"]
    TypeOrm["TypeOrmModule"]

    App --> Auth
    App --> User
    App --> Quiz
    App --> Mail
    Auth --> Mail
    Auth --> User
    Auth --> Passport
    Auth --> JWT
    User --> TypeOrm
    Quiz --> TypeOrm
```

---

### Services Class Diagram

A breakdown of each service's public interface and how services depend on one another. `+` denotes public methods, `-` denotes private methods.

```mermaid
classDiagram
class AuthService {
+createUser()
+validateGoogleUser()
+validateLocalUser()
+resetPassword()
+changePassword()
-generateOtp()
+verifyOtp()
+resendOtp()
+sendOtp()
+forgotPassword()
+logout()
+generateTokens()
+refreshTokens()
+generateOAuthCode()
+consumeOAuthCode()
}
class UserService {
+createUser()
+findOne()
+findDeletedByEmail()
+findOrCreateGoogleUser()
+deleteUser()
+updateUser()
+saveToken()
+getToken()
+clearToken()
+incrementAttempts()
+verifyUser()
}
class QuizService {
+getQuizzes()
+getQuestionsByQuiz()
+getAnswersByQuestion()
+getPassedQuizzesBadges()
+getUserQuizAnswer()
+getQuizProgress()
+startQuiz()
+insertUserProgress()
+pauseQuiz()
+getActivities()
+getUserStats()
+getLeaderboard()
}
class MailService {
+sendResetPasswordEmail()
+sendOtpEmail()
}

    AuthService --> UserService : uses
    AuthService --> MailService: uses

```

---

### Data Flow Diagram

Shows how data moves through the system between users, processes, and the database.

```mermaid
graph TD
    U(["User"])

    subgraph Processes
        P1["1.0 Register / Login"]
        P2["2.0 OAuth"]
        P3["3.0 Manage Quizzes"]
        P4["4.0 Track Progress"]
        P5["5.0 Submit Answers"]
        P6["6.0 Rank Leaderboard"]
        P7["7.0 Delete Account"]

    end

    subgraph Database
        DS1[("User")]
        DS2[("Token")]
        DS3[("DeletedUser")]
        DS4[("Quizzes")]
        DS5[("Questions")]
        DS6[("Answers")]
        DS7[("User Quiz Progress")]
        DS8[("User Quiz Answers")]
    end

    U -->|"credentials"| P1
    P1 -->|"check deleted"| DS3
    P1 -->|"store user"| DS1
    P1 -->|"JWT token"| U

    U ---> |"authorize"| P2
    P2 -->|"store oauth code"| DS2
    P2 ---> |"redirect with code"| U
    U ---> |"send code"| P2
    P2 ---> |"validate code"| DS2
    P2 ---> |"generate tokens"| U

    U -->|"request quizzes"| P3
    P3 -->|"fetch quizzes"| DS4
    DS4 -->|"quiz data"| P3
    P3 -->|"quiz list"| U

    U -->|"start / pause quiz"| P4
    P4 -->|"read / write progress"| DS7
    DS7 -->|"progress state"| P4
    P4 -->|"progress state"| U

    U -->|"selected answer"| P5
    P5 -->|"validate answer"| DS6
    P5 -->|"store answer"| DS8
    DS8 -->|"score result"| P5
    P5 -->|"score result"| U

    U -->|"request leaderboard"| P6
    P6 -->|"aggregate scores"| DS7
    P6 -->|"ranked results"| U

    U -->|"delete request"| P7
    P7 -->|"delete user"| DS1
    P7 -->|"revoke tokens"| DS2
    P7 -->|"store email"| DS3
    P7 -->|"confirmed"| U
```

---

### 🗄️ Database Schema

The following diagram represents the relational structure of the Quizzer database, including user authentication, quiz management, progress tracking, and answer submission.

```mermaid
erDiagram
  users {
    uuid id PK
    string name
    string email
    string password
    string googleId
    string providers
    boolean isEmailVerified
  }
  tokens {
    uuid id PK
    string token
    enum type
    date expiresAt
    int attempts
    date lastSentAt
    date createdAt
    uuid userId FK
  }
  deleted_users {
    uuid id PK
    string email
    date deletedAt
  }
  quizzes {
    uuid id PK
    string title
    text description
    int timeInSeconds
    string badgeIcon
    string badgeTitle
  }
  questions {
    uuid id PK
    uuid quizId FK
    text text
    int orderIndex
  }
  answers {
    uuid id PK
    uuid questionId FK
    varchar text
    boolean isCorrect
    int orderIndex
  }
  user_quiz_progress {
    uuid id PK
    uuid userId FK
    uuid quizId FK
    uuid pausedAtQuestionId FK
    enum status
    numeric score
    boolean passed
    int remainingTimeSeconds
    date attemptAt
    date completedAt
  }
  user_quiz_answers {
    uuid id PK
    uuid userId FK
    uuid quizId FK
    uuid questionId FK
    uuid selectedAnswerId FK
    boolean isCorrect
  }

  users ||--o{ tokens : "has"
  users ||--o{ user_quiz_progress : "tracks"
  users ||--o{ user_quiz_answers : "submits"
  quizzes ||--o{ questions : "contains"
  questions ||--o{ answers : "has"
  quizzes ||--o{ user_quiz_progress : "tracked by"
  quizzes ||--o{ user_quiz_answers : "answered in"
  questions ||--o{ user_quiz_answers : "answered as"
  answers ||--o{ user_quiz_answers : "selected as"
  questions ||--o| user_quiz_progress : "paused at"
```

---

## 📄 License

MIT License

---

<div align="center">
  Built with ❤️ by <a href="https://github.com/Ahmed-Elgammal-900">Ahmed Elgammal</a>
</div>
