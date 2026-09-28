# 🌾 AgriFlow
### Smart Agricultural Procurement Management System | SIH 2026

AgriFlow is a web-based agricultural procurement management system designed to reduce long waiting times, lack of procurement information, and uncertainty faced by farmers at procurement centers.

The platform connects farmers and procurement officers through a transparent digital workflow — from submitting a procurement request to scheduling, digital token generation, live queue management and final procurement receipt.

---

## 🎯 Problem Statement

Farmers often face:

- Long waiting times at procurement centers
- Lack of information about procurement schedules
- Uncertainty regarding procurement status
- Congestion at procurement centers
- Limited visibility of queue position and expected waiting time

AgriFlow addresses these problems through digital scheduling, queue management and real-time procurement status tracking.

---

## 💡 Our Solution

AgriFlow creates a structured procurement journey:

**Farmer Registration → Procurement Request → Officer Approval → Smart Scheduling → Digital Token → Farmer Check-In → Live Queue → Procurement Processing → Digital Receipt**

This helps farmers know **when to arrive, where to go and what their current procurement status is** before reaching the procurement center.

---

## 🚀 Key Features

### 👨‍🌾 Farmer Dashboard
- Farmer registration and secure login
- Submit crop procurement requests
- View upcoming procurement schedules
- Track procurement status
- Procurement Journey visualization
- Notifications for status updates

### 🎫 Digital Token & Smart Queue
- Automatic digital token generation
- Queue position
- Farmers ahead
- Estimated waiting time
- Procurement center information
- Farmer check-in at procurement center

### 🧑‍💼 Procurement Officer Dashboard
- Manage farmer procurement requests
- Approve, schedule or update requests
- Create procurement schedules
- Monitor center capacity
- View checked-in farmers
- Process farmers through the live queue

### 📊 Decision Intelligence
- Active procurement quantity
- Completed procurement quantity
- Capacity utilization
- Crop-wise procurement demand
- Highest-demand crop identification
- Capacity / overload alerts

### 🧾 Digital Procurement Receipt
After successful procurement, farmers receive a digital acknowledgement containing procurement details that can also be printed.

---

## ⚙️ Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python + FastAPI |
| Frontend | HTML, CSS, JavaScript |
| Database | PostgreSQL |
| ORM | SQLAlchemy |
| Authentication | JWT |
| Password Security | Argon2 |
| Server | Uvicorn |
| Development | Visual Studio Code |
| Version Control | Git & GitHub |

---

## 🔄 System Workflow

```text
FARMER
   ↓
Register / Login
   ↓
Submit Procurement Request
   ↓
Select Crop + Quantity + Center
   ↓
PROCUREMENT OFFICER
   ↓
Review & Schedule Request
   ↓
Smart Schedule Allocation
   ↓
Digital Token Generated
   ↓
Farmer Views Queue Position & Estimated Wait
   ↓
Farmer Check-In
   ↓
Live Procurement Queue
   ↓
Call Next → Start Procurement → Complete
   ↓
Digital Procurement Receipt