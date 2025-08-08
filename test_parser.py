from app.utils import parse_log_file

df = parse_log_file('data/auth.log')

print(df.head())
print("\nShape:", df.shape)
print("\nColumns:", df.columns.tolist())
