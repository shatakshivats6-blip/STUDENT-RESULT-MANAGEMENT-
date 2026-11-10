// UNIQUE FEATURE: Marks Anomaly Detector (Z-score, IQR fences and internal/external gap rule)
#include <ctime>
#include <fstream>
#include <iomanip>
#include <map>
#include "Feature.h"
#include "Utils.h"
 
namespace {
 
enum class Severity { WARNING = 1, CRITICAL = 2 };
 
struct Anomaly {
    std::string uid, name, code, rule, detail;
    Severity severity;
};
 
class AnomalyDetector {
    const ResultManager& rm_;
    double zLimit_ = 2.0;       // |z| above this is suspicious
    double iqrK_ = 1.5;         // Tukey fence multiplier
    double gapLimit_ = 35.0;    // percentage-point gap between internal% and external%
 
    static std::string num(double v, int p = 2) {
        std::ostringstream o;
        o << std::fixed << std::setprecision(p) << v;
        return o.str();
    }
 
public:
    explicit AnomalyDetector(const ResultManager& rm) : rm_(rm) {}
 
    void setThresholds(double z, double k, double gap) { zLimit_ = z; iqrK_ = k; gapLimit_ = gap; }
    double zLimit() const { return zLimit_; }
    double iqrK() const { return iqrK_; }
    double gapLimit() const { return gapLimit_; }
 
    std::vector<Anomaly> scan() const {
        if (rm_.size() < 4) throw ResultException("At least 4 students are needed for statistical checks");
        std::vector<Anomaly> out;
        for (const SubjectMark& sub : ResultManager::catalogue()) {
            std::vector<double> totals;
            for (const Student& s : rm_.all())
                for (const SubjectMark& m : s.marks()) if (m.code == sub.code) totals.push_back(m.total());
            double mu = util::mean(totals), sd = util::stddev(totals);
            double q1 = util::quantile(totals, 0.25), q3 = util::quantile(totals, 0.75);
            double lo = q1 - iqrK_ * (q3 - q1), hi = q3 + iqrK_ * (q3 - q1);
 
            for (const Student& s : rm_.all()) {
                for (const SubjectMark& m : s.marks()) {
                    if (m.code != sub.code) continue;
                    double z = sd > 0 ? (m.total() - mu) / sd : 0.0;
                    if (std::abs(z) > zLimit_)
                        out.push_back({s.id(), s.name(), m.code, "Z-SCORE",
                                       "total " + num(m.total(), 0) + " (z = " + num(z) + ")",
                                       std::abs(z) >= 2.5 ? Severity::CRITICAL : Severity::WARNING});
                    if (m.total() < lo || m.total() > hi)
                        out.push_back({s.id(), s.name(), m.code, "IQR-FENCE",
                                       "total " + num(m.total(), 0) + " outside [" + num(lo, 1) + ", " + num(hi, 1) + "]",
                                       Severity::WARNING});
                    double ip = m.internal * 100.0 / SubjectMark::MAX_INTERNAL;
                    double ep = m.external * 100.0 / SubjectMark::MAX_EXTERNAL;
                    if (std::abs(ip - ep) >= gapLimit_)
                        out.push_back({s.id(), s.name(), m.code, "GAP",
                                       "internal " + num(ip, 0) + "% vs external " + num(ep, 0) + "%",
                                       std::abs(ip - ep) >= 50 ? Severity::CRITICAL : Severity::WARNING});
                }
            }
        }
        std::sort(out.begin(), out.end(), [](const Anomaly& a, const Anomaly& b) {
            if (a.severity != b.severity) return a.severity > b.severity;
            return a.uid < b.uid;
        });
        return out;
    }
 
    void printReport(const std::vector<Anomaly>& v, std::ostream& os) const {
        os << "Thresholds: |z| > " << zLimit_ << ", IQR k = " << iqrK_ << ", gap >= " << gapLimit_ << " pts\n"
           << std::left << std::setw(10) << "Severity" << std::setw(12) << "UID" << std::setw(16) << "Name"
           << std::setw(9) << "Subject" << std::setw(11) << "Rule" << "Detail\n" << util::line('-', 90) << "\n";
        for (const auto& a : v)
            os << std::left << std::setw(10) << (a.severity == Severity::CRITICAL ? "CRITICAL" : "WARNING")
               << std::setw(12) << a.uid << std::setw(16) << a.name.substr(0, 15) << std::setw(9) << a.code
               << std::setw(11) << a.rule << a.detail << "\n";
        os << util::line('-', 90) << "\nFlags raised: " << v.size() << "\n";
        if (v.empty()) os << "No anomalies detected.\n";
    }
 
    void writeAuditLog(const std::vector<Anomaly>& v, const std::string& path) const {
        std::ofstream f(path, std::ios::app);
        if (!f) throw ResultException("Cannot open audit log " + path);
        std::time_t t = std::time(nullptr);
        char buf[32];
        std::strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S", std::localtime(&t));
        f << "=== Audit run " << buf << " | students: " << rm_.size() << " | flags: " << v.size() << " ===\n";
        for (const auto& a : v)
            f << (a.severity == Severity::CRITICAL ? "CRITICAL" : "WARNING") << ',' << a.uid << ',' << a.code
              << ',' << a.rule << ',' << a.detail << '\n';
    }
};
 
}  // namespace
 
std::string featureName() { return "Marks Anomaly Detector & Audit Log"; }
 
void runSpecialFeature(ResultManager& rm) {
    AnomalyDetector det(rm);
    while (true) {
        std::cout << "\n--- ANOMALY DETECTOR ---\n 1. Run full scan\n 2. Change thresholds\n"
                  << " 3. Run scan and append to audit_log.txt\n 0. Back\n";
        int c = util::readInt("Choice: ", 0, 3);
        if (c == 0) return;
        if (c == 2) {
            double z = util::readNumber("Z-score limit (1-4): ", 1, 4);
            double k = util::readNumber("IQR multiplier (0.5-3): ", 0.5, 3);
            double g = util::readNumber("Internal/external gap in points (10-80): ", 10, 80);
            det.setThresholds(z, k, g);
            std::cout << "Thresholds updated.\n";
            continue;
        }
        auto found = det.scan();
        det.printReport(found, std::cout);
        if (c == 3) { det.writeAuditLog(found, "audit_log.txt"); std::cout << "Appended to audit_log.txt\n"; }
    }
}
```[cite: 1]