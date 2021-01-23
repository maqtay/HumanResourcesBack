package com.maqtay.HumanResourcesBack.repository;

import com.maqtay.HumanResourcesBack.models.ConfigurationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.CrudRepository;

public interface ConfirmationTokenRepository extends JpaRepository<ConfigurationToken, String> {
    ConfigurationToken findByConfirmationToken(String confirmationToken);
}
