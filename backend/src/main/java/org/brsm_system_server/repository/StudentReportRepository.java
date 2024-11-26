package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Report;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StudentReportRepository extends JpaRepository<Report, Long> {
}
