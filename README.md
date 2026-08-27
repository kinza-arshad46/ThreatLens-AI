# 📉 Why Customers Leave: Customer Churn Analysis, Segmentation & Prediction

### A complete, business-driven approach to understanding, segmenting, and predicting customer churn

![Python](https://img.shields.io/badge/Python-3.x-blue?logo=python&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-ML-orange?logo=scikitlearn&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-Model-green)
![SHAP](https://img.shields.io/badge/SHAP-Explainability-purple)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen)
![License](https://img.shields.io/badge/License-MIT-lightgrey)

---

## 📌 Business Problem

Customer churn is one of the most expensive problems a subscription-based business can face — acquiring a new customer typically costs far more than retaining an existing one. This project takes an end-to-end, business-first approach with three goals:

1. **Understand** *why* customers churn through structured, question-driven exploratory analysis.
2. **Segment** customers into actionable groups based on value and churn risk.
3. **Predict** which customers are likely to churn using a leakage-safe, cross-validated machine-learning pipeline — and explain *why* the model makes those predictions.

The end goal isn't a single accuracy number — it's a set of **concrete, defensible business recommendations**.

---

## 🗂️ Dataset

**[Telco Customer Churn](https://www.kaggle.com/datasets/blastchar/telco-customer-churn)** — IBM Sample Data Set, published on Kaggle by *blastchar*.

Each row represents one customer at a telecom company, with:

| Category | Fields |
|---|---|
| **Demographics** | gender, senior citizen status, partner, dependents |
| **Account info** | tenure, contract type, payment method, paperless billing, monthly & total charges |
| **Services** | phone, internet, online security, backup, device protection, tech support, streaming TV/movies |
| **Target** | `Churn` (Yes/No) |

> No rows or columns were removed from the original data, and no synthetic records were added. `TotalCharges` was converted from string to numeric, missing values for zero-tenure customers filled with 0, and `SeniorCitizen` recoded from 0/1 to Yes/No for readability.

---

## 🧭 Approach

```
Question-driven EDA  →  Unsupervised Value/Risk Segmentation (K-Means)
        →  Feature Engineering + Leakage-Safe Train/Test Split
        →  5 Candidate Classifiers, compared via 5-fold CV ROC-AUC
        →  Hyperparameter Tuning (RandomizedSearchCV) on top 2 models
        →  Single Final Evaluation on the Untouched Test Set
        →  Feature Importance + SHAP for Explainability
        →  Business Recommendations
```

The model is selected **purely on cross-validated training performance**, never on test-set performance — the test set is touched exactly once, for final reporting only, to avoid optimistic bias.

---

## 🔍 Key Findings

- Churn is concentrated among a **specific, targetable customer profile**: new customers (low tenure), on **month-to-month contracts**, paying **higher monthly charges**, via **electronic check**, without add-on services like Online Security or Tech Support.
- The **interaction** between factors matters more than any single one — month-to-month customers in their **first 0–12 months** are the single highest-risk group in the dataset.
- Segmentation reframes the problem from *"who churns?"* to *"who is valuable **and** at risk?"* — the **High Value – High Risk** segment is where retention spend has the highest expected return.

---

## 🤖 Modeling

Five candidate classifiers were compared using **5-fold stratified cross-validation** (ROC-AUC, Recall, F1, PR-AUC), with the top two tuned via `RandomizedSearchCV`:

- Logistic Regression
- Decision Tree
- Random Forest
- Gradient Boosting
- XGBoost

Class imbalance was handled via `class_weight='balanced'` (and `scale_pos_weight` for XGBoost). The final model is evaluated once on the held-out test set, with full ROC and Precision-Recall curves included in the notebook.

---

## 🧠 Explainable ML

Feature importance and **SHAP** values are used to connect model predictions back to concrete business drivers — confirming that the model is learning genuine signal (contract type, tenure, monthly charges, payment method, add-on services) rather than spurious noise, and closing the loop from raw data → statistical patterns → model confirmation → business action.

---

## 💡 Business Recommendations

| Risk Pattern | Recommended Action |
|---|---|
| Month-to-month contract, low tenure | Discounted incentive to upgrade to a 1- or 2-year contract in the first 3 months |
| High monthly charges + low tenure | Proactive "early tenure" retention outreach — loyalty discount or bundled service credit |
| High Value – High Risk segment | Priority personalized retention campaign — assign account outreach, not just automated email |
| No Online Security / Tech Support | A/B test a free trial of these add-ons for at-risk customers before scaling the offer |
| Electronic check payment | Encourage migration to automatic payment with a small incentive |
| New customers (tenure < 6 months) | Strengthen onboarding — proactive check-ins during the highest-risk window |

**Operationally:** score the active customer base monthly, rank by predicted churn probability, cross-reference with the value segment, and route the **High Value – High Risk** list to the retention team first.

> All patterns above are **observed associations**, not proven causal effects, and should be validated with controlled experiments (e.g. A/B tests) before scaling.

---

## 📁 Repository Structure

```
├── customer-churn-analysis-segmentation-prediction.ipynb   # Full end-to-end notebook
└── README.md
```

---

## ⚙️ How to Run

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/<repo-name>.git
   cd <repo-name>
   ```
2. Install dependencies:
   ```bash
   pip install numpy pandas matplotlib seaborn scikit-learn xgboost shap
   ```
3. Download the [Telco Customer Churn dataset](https://www.kaggle.com/datasets/blastchar/telco-customer-churn) from Kaggle and place the CSV in the project folder.
4. Launch the notebook:
   ```bash
   jupyter notebook customer-churn-analysis-segmentation-prediction.ipynb
   ```

---

## 📑 Notebook Contents

1. Business Problem
2. Dataset Overview
3. Data Quality Assessment & Cleaning
4. Exploratory Data Analysis
5. Customer Segmentation
6. Feature Engineering
7. Model Building
8. Cross-Validated Model Comparison
9. Hyperparameter Optimization
10. Final Test Evaluation
11. Explainable ML
12. Business Recommendations
13. Limitations & Next Steps
14. Conclusion

---

## ⚠️ Limitations

- The dataset represents a single telecom company at one point in time — results may not generalize elsewhere.
- All associations are correlational, not causal, and should be validated with A/B tests before any offer is scaled.
- No support-interaction, satisfaction, or time-varying behavioral data is included — likely a source of additional churn signal.
- Future work: cost-sensitive learning, probability calibration, temporal/sequential features, and a formal deployment + monitoring plan.

---

## 🙌 Acknowledgements

Dataset: **Telco Customer Churn**, IBM sample dataset published on Kaggle by [blastchar](https://www.kaggle.com/datasets/blastchar/telco-customer-churn). Provided for educational and analytical use — see the dataset page for exact license terms before commercial use.

---

## ⭐ Support

If you found this project useful, please consider giving the repository a **star** ⭐ — feedback and suggestions are always welcome!
