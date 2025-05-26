def parse_days(n_days: int) -> str:
    years = n_days // 365
    months = (n_days % 365) // 30
    days = (n_days % 365) % 30
    result = []
    if years > 0:
        result.append(str(years) + " ano" if years == 1 else str(years) + " anos")
    if months > 0:
        result.append(str(months) + " mês" if months == 1 else str(months) + " meses")
    if days > 0:
        result.append(str(days) + " dia" if days == 1 else str(days) + " dias")
    return ", ".join(result) if result else "0 dias"