from app.services.analyzers.mutation_generator import MutationGenerator


def test_context_aware_mutations():
    gen = MutationGenerator()

    # 1. ID Mutations (BOLA)
    id_mutations = gen.generate_mutations_for_parameter("patient_id", "string", "path", "BOLA")
    mutation_types = [m.mutation_type for m in id_mutations]
    assert "cross_tenant_id" in mutation_types
    assert "negative_id" in mutation_types
    assert "nonexistent_id" in mutation_types

    # 2. Financial Amount Mutations
    amount_mutations = gen.generate_mutations_for_parameter("price", "number", "body")
    amt_types = [m.mutation_type for m in amount_mutations]
    assert "negative_amount" in amt_types
    assert "zero_amount" in amt_types

    # 3. Role Mutations
    role_mutations = gen.generate_mutations_for_parameter("user_role", "string", "body")
    role_types = [m.mutation_type for m in role_mutations]
    assert "admin_role_escalation" in role_types
    assert "null_role_injection" in role_types

    # 4. Age / Count Mutations
    age_mutations = gen.generate_mutations_for_parameter("age", "integer", "query")
    age_types = [m.mutation_type for m in age_mutations]
    assert "negative_numeric" in age_types
    assert "large_value_dos" in age_types
