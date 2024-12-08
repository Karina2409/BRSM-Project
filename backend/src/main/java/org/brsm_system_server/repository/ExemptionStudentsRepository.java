package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Exemption;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.transaction.annotation.Transactional;

public interface ExemptionStudentsRepository extends JpaRepository<Exemption, Long> {

    @Modifying
    @Transactional
    @Query(value = "DELETE FROM exemption_students WHERE student_id = :studentId", nativeQuery = true)
    void deleteAllExemptionStudents(@Param("studentId") Long studentId);
}
