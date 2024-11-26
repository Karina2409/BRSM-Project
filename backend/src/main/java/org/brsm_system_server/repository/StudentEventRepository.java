package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Student;
import org.springframework.data.jpa.repository.JpaRepository;

public interface StudentEventRepository extends JpaRepository<Student, Long> {
}
