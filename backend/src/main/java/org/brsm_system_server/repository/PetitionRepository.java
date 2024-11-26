package org.brsm_system_server.repository;

import org.brsm_system_server.entity.Petition;
import org.springframework.data.jpa.repository.JpaRepository;

public interface PetitionRepository extends JpaRepository<Petition, Long> {
}
