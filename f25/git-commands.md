# Git Commands Quick Reference - CSCI 347

## Essential Daily Commands

### Check Status
```bash
git status                  # See current branch and file changes
git branch                  # List all branches (* = current)
git log --oneline -5        # Show recent commits
```

### Start New Assignment
```bash
git checkout main           # Switch to main branch
git pull upstream main      # Get latest course updates
git push origin main        # Update your fork
git checkout -b week##-assignment-name  # Create feature branch
```

### Work on Assignment
```bash
git add .                   # Stage all changes
git add specific_file.cpp   # Stage specific file
git commit -m "Clear description"  # Commit changes
git push origin branch-name # Push to your fork
```

## Initial Setup Commands (One Time Only)

### Fork Setup
```bash
# After forking on GitHub, clone your fork:
git clone https://github.com/YOUR_USERNAME/csci347.git
cd csci347
git remote add upstream https://github.com/INSTRUCTOR_USERNAME/csci347.git
```

### Configure Identity
```bash
git config user.name "FirstName LastName - CSCI347_f25"
git config user.email "your.email@university.edu"
```

### Create Assignment Directory
```bash
mkdir -p assignments/CSCI347_f25_FirstName_LastName
```

## Branch Management

### Creating Branches
```bash
git checkout -b new-branch-name     # Create and switch to new branch
git checkout existing-branch        # Switch to existing branch
git branch                          # List all branches
```

### Naming Conventions
```bash
git checkout -b week01-crypto-assignment
git checkout -b week03-pki-certificates  
git checkout -b week04-authentication
```

### Cleaning Up Branches
```bash
git branch -d branch-name              # Delete local branch
git push origin --delete branch-name  # Delete remote branch
```

## Synchronization Commands

### Keep Fork Updated
```bash
# Run this before starting each assignment:
git checkout main
git pull upstream main
git push origin main
```

### Update Feature Branch
```bash
# If main has new changes while you're working:
git checkout main
git pull upstream main
git checkout your-feature-branch
git merge main
```

## Commit Best Practices

### Good Commit Messages
```bash
git commit -m "Implement password vault functionality

- Add AES encryption with secure key derivation
- Add password generation with entropy validation  
- Include comprehensive security tests"
```

### Commit Frequently
```bash
git add .
git commit -m "Add basic encryption structure"
git commit -m "Implement secure key handling"
git commit -m "Add security validation tests"
git commit -m "Update security documentation"
```

## Pull Request Commands

### Submit for Review
```bash
# After final commit:
git push origin your-branch-name
# Then create PR on GitHub
```

### Address PR Feedback
```bash
# Make requested changes, then:
git add .
git commit -m "Address PR feedback: fix encryption vulnerability"
git push origin your-branch-name
# PR updates automatically
```

## Troubleshooting Commands

### See What Changed
```bash
git diff                    # Show unstaged changes
git diff --staged          # Show staged changes  
git diff HEAD~1            # Compare with previous commit
```

### Undo Changes
```bash
git checkout -- file.py    # Discard unstaged changes to file
git reset HEAD file.py      # Unstage file (keep changes)
git reset --hard HEAD       # Discard ALL unstaged changes (⚠️ dangerous)
```

### Fix Last Commit
```bash
git commit --amend -m "Better commit message"  # Fix commit message
git add forgotten_file.py
git commit --amend --no-edit                   # Add file to last commit
```

### Resolve Merge Conflicts
```bash
git status                  # See conflicted files
# Edit files (look for <<<< ==== >>>>)
git add .                   # Mark conflicts as resolved
git commit -m "Resolve merge conflicts"
```

## Information Commands

### Repository Status
```bash
git remote -v               # Show all remotes
git log --graph --oneline   # Visual commit history
git show                    # Show latest commit details
```

### File History
```bash
git log -- file.py          # Show commits affecting specific file
git blame file.py           # Show who changed each line
```

## Emergency Commands

### Accidentally on Main Branch
```bash
# If you made changes on main instead of feature branch:
git checkout -b week01-crypto-assignment  # Create branch with current changes
# Now you're on the correct branch!
```

### Lost Changes
```bash
git reflog                  # Show recent actions
git checkout HEAD@{2}       # Go back to specific state
```

### Need to Start Over
```bash
git checkout main
git pull upstream main
git checkout -b week01-crypto-assignment-v2
# Copy your work manually if needed
```

## Common Error Solutions

### "Branch already exists"
```bash
git checkout existing-branch-name     # Switch to it instead
# OR delete it first:
git branch -d old-branch-name
git checkout -b week01-crypto-assignment
```

### "Nothing to commit"
```bash
git status                  # Check if files are staged
git add .                   # Stage files if needed
```

### "Merge conflict"
1. `git status` shows conflicted files
2. Open files and look for `<<<<`, `====`, `>>>>` markers
3. Edit to resolve conflicts
4. `git add .` and `git commit -m "Resolve conflicts"`

### "Permission denied"
- Check if you're pushing to your fork (origin), not upstream
- Verify GitHub credentials/tokens are set up

## Workflow Checklist

### Before Each Assignment:
- [ ] `git checkout main`
- [ ] `git pull upstream main` 
- [ ] `git push origin main`
- [ ] `git checkout -b week##-assignment-name`

### During Assignment:
- [ ] Work in your assignment directory
- [ ] `git add .` and `git commit -m "..."` frequently
- [ ] `git push origin branch-name` regularly

### Submitting Assignment:
- [ ] Final `git push origin branch-name`
- [ ] Create Pull Request on GitHub
- [ ] Fill out PR template completely
- [ ] Wait for review and address feedback

### After PR Merged:
- [ ] `git checkout main`
- [ ] `git pull upstream main`
- [ ] `git branch -d old-branch-name`

---

**💡 Pro Tips:**
- Use `git status` frequently to stay oriented
- Commit early and often - you can always squash later  
- Read error messages carefully - they usually tell you exactly what to do
- When in doubt, ask for help rather than forcing commands
- Keep this reference handy until commands become muscle memory!