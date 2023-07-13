using DemoMinimalAPI.Models;
using Microsoft.EntityFrameworkCore;

namespace DemoMinimalAPI.Data;

public class MinimalContextDb : DbContext {
    public MinimalContextDb(DbContextOptions<MinimalContextDb> options) : base(options) { }

    public DbSet<Supplier> Suppliers { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder) {
        modelBuilder.Entity<Supplier>()
            .HasKey(p => p.Id);

        modelBuilder.Entity<Supplier>()
            .Property(p => p.Name)
            .IsRequired()
            .HasColumnType("varchar(200)");

        modelBuilder.Entity<Supplier>()
            .Property(p => p.Document)
            .IsRequired()
            .HasColumnType("varchar(14)");

        modelBuilder.Entity<Supplier>()
            .ToTable("Suppliers");

        base.OnModelCreating(modelBuilder);
    }
}